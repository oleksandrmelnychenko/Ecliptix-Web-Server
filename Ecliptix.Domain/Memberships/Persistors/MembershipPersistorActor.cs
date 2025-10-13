using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Utilities;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Microsoft.EntityFrameworkCore.Storage;
using Serilog;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MembershipPersistorActor : PersistorBase<VerificationFlowFailure>
{
    private static readonly Dictionary<string, ProtoMembership.Types.ActivityStatus> MembershipStatusMap = new()
    {
        ["active"] = ProtoMembership.Types.ActivityStatus.Active,
        ["inactive"] = ProtoMembership.Types.ActivityStatus.Inactive
    };

    public MembershipPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }


    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new MembershipPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        Receive<UpdateMembershipSecureKeyEvent>(cmd =>
            ExecuteWithContext(ctx => UpdateMembershipSecureKeyAsync(ctx, cmd), "UpdateMembershipSecureKey")
                .PipeTo(Sender));

        Receive<CreateMembershipActorEvent>(cmd =>
            ExecuteWithContext(ctx => CreateMembershipAsync(ctx, cmd), "CreateMembership")
                .PipeTo(Sender));

        Receive<SignInMembershipActorEvent>(cmd =>
            ExecuteWithContext(ctx => SignInMembershipAsync(ctx, cmd), "LoginMembership")
                .PipeTo(Sender));

        Receive<GetMembershipByVerificationFlowEvent>(cmd =>
            ExecuteWithContext(ctx => GetMembershipByVerificationFlowAsync(ctx, cmd), "GetMembershipByVerificationFlow")
                .PipeTo(Sender));

        Receive<GetMembershipByUniqueIdEvent>(cmd =>
            ExecuteWithContext(ctx => GetMembershipByUniqueIdAsync(ctx, cmd), "GetMembershipByUniqueId")
                .PipeTo(Sender));

        Receive<ValidatePasswordRecoveryFlowEvent>(cmd =>
            ExecuteWithContext(ctx => ValidatePasswordRecoveryFlowAsync(ctx, cmd), "ValidatePasswordRecoveryFlow")
                .PipeTo(Sender));

        Receive<ExpirePasswordRecoveryFlowsEvent>(cmd =>
            ExecuteWithContext(ctx => ExpirePasswordRecoveryFlowsAsync(ctx, cmd), "ExpirePasswordRecoveryFlows")
                .PipeTo(Sender));

        ReceiveAsync<UpdateMembershipVerificationFlowEvent>(async cmd =>
        {
            Log.Information("[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Received UpdateMembershipVerificationFlowEvent for FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}",
                cmd.VerificationFlowId, cmd.Purpose, cmd.FlowStatus);

            Result<Unit, VerificationFlowFailure> result = await ExecuteWithContext(
                ctx => UpdateMembershipVerificationFlowAsync(ctx, cmd),
                "UpdateMembershipVerificationFlow");

            result.Match<Unit>(
                ok =>
                {
                    Log.Information("[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Successfully processed event for FlowId: {FlowId}", cmd.VerificationFlowId);
                    return Unit.Value;
                },
                err =>
                {
                    Log.Error("[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Failed to process event for FlowId: {FlowId}, Error: {Error}",
                        cmd.VerificationFlowId, err.Message);
                    return Unit.Value;
                }
            );

            // Send result back to sender (for Ask pattern)
            Sender.Tell(result);
        });
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> SignInMembershipAsync(
        EcliptixSchemaContext ctx, SignInMembershipActorEvent cmd)
    {
        const int lockoutDurationMinutes = 5;
        const int maxAttemptsInPeriod = 5;

        try
        {
            DateTime currentTime = DateTime.UtcNow;

            LoginAttemptEntity? lockoutMarker = await LoginAttemptQueries.GetMostRecentLockout(ctx, cmd.MobileNumber);
            if (lockoutMarker?.LockedUntil != null)
            {
                if (currentTime < lockoutMarker.LockedUntil.Value)
                {
                    int remainingMinutes = (int)Math.Ceiling((lockoutMarker.LockedUntil.Value - currentTime).TotalMinutes);
                    return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded(remainingMinutes.ToString()));
                }
                else
                {
                    await ctx.LoginAttempts
                        .Where(la => la.MobileNumber == cmd.MobileNumber &&
                                     la.Timestamp <= lockoutMarker.Timestamp &&
                                     !la.IsDeleted)
                        .ExecuteDeleteAsync();
                }
            }

            DateTime fiveMinutesAgo = currentTime.AddMinutes(-5);
            int failedCount = await LoginAttemptQueries.CountFailedSince(ctx, cmd.MobileNumber, fiveMinutesAgo);

            if (failedCount >= maxAttemptsInPeriod)
            {
                DateTime lockedUntil = currentTime.AddMinutes(lockoutDurationMinutes);
                LoginAttemptEntity lockoutAttempt = new()
                {
                    MobileNumber = cmd.MobileNumber,
                    LockedUntil = lockedUntil,
                    Outcome = "rate_limit_exceeded",
                    IsSuccess = false,
                    Timestamp = currentTime,
                    AttemptedAt = currentTime
                };
                ctx.LoginAttempts.Add(lockoutAttempt);
                await ctx.SaveChangesAsync();

                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded(lockoutDurationMinutes.ToString()));
            }

            if (string.IsNullOrEmpty(cmd.MobileNumber))
            {
                await LogLoginAttemptAsync(ctx, cmd.MobileNumber, "mobile_number_cannot_be_empty", false);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.MobileNumberCannotBeEmpty));
            }

            MembershipEntity? membership = await MembershipQueries.GetByMobileNumber(ctx, cmd.MobileNumber);
            if (membership == null)
            {
                await LogLoginAttemptAsync(ctx, cmd.MobileNumber, "mobile_number_not_found", false);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.MobileNotFound));
            }

            if (membership.SecureKey == null || membership.SecureKey.Length == 0)
            {
                await LogLoginAttemptAsync(ctx, cmd.MobileNumber, "secure_key_not_set", false);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.SecureKeyNotSet));
            }

            if (membership.Status != "active")
            {
                await LogLoginAttemptAsync(ctx, cmd.MobileNumber, "inactive_membership", false);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.InactiveMembership));
            }

            await LogLoginAttemptAsync(ctx, cmd.MobileNumber, "success", true);

            await ctx.LoginAttempts
                .Where(la => la.MobileNumber == cmd.MobileNumber &&
                             (!la.IsSuccess || la.LockedUntil != null) &&
                             !la.IsDeleted)
                .ExecuteDeleteAsync();

            return MapActivityStatus(membership.Status).Match(
                activityStatus => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = membership.UniqueId,
                        ActivityStatus = activityStatus,
                        CreationStatus = ProtoMembership.Types.CreationStatus.OtpVerified,
                        CredentialsVersion = membership.CredentialsVersion,
                        SecureKey = membership.SecureKey ?? [],
                        MaskingKey = membership.MaskingKey ?? []
                    }),
                () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
            );
        }
        catch (Exception ex)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Login failed: {ex.Message}"));
        }
    }

    private static async Task LogLoginAttemptAsync(EcliptixSchemaContext ctx, string mobileNumber, string outcome, bool isSuccess)
    {
        LoginAttemptEntity attempt = new LoginAttemptEntity
        {
            MobileNumber = mobileNumber,
            Outcome = outcome,
            IsSuccess = isSuccess,
            Timestamp = DateTime.UtcNow,
            AttemptedAt = DateTime.UtcNow
        };
        ctx.LoginAttempts.Add(attempt);
        await ctx.SaveChangesAsync();
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> UpdateMembershipSecureKeyAsync(
        EcliptixSchemaContext ctx, UpdateMembershipSecureKeyEvent cmd)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();
        try
        {
            if (cmd.SecureKey.Length == 0)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("Secure key cannot be empty"));
            }

            if (cmd.MaskingKey.Length != 32)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("Masking key must be exactly 32 bytes"));
            }

            MembershipEntity? membership = await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipIdentifier);
            if (membership == null)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("Membership not found or deleted"));
            }

            int rowsAffected = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.SecureKey, cmd.SecureKey)
                    .SetProperty(m => m.MaskingKey, cmd.MaskingKey)
                    .SetProperty(m => m.Status, "active")
                    .SetProperty(m => m.CreationStatus, "secure_key_set")
                    .SetProperty(m => m.CredentialsVersion, m => m.CredentialsVersion + 1)
                    .SetProperty(m => m.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
            {
                await transaction.RollbackAsync();
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess("Failed to update membership"));
            }

            await transaction.CommitAsync();

            int newCredentialsVersion = membership.CredentialsVersion + 1;

            return MapActivityStatus("active").Match(
                status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = cmd.MembershipIdentifier,
                        ActivityStatus = status,
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum("secure_key_set"),
                        CredentialsVersion = newCredentialsVersion,
                        MaskingKey = cmd.MaskingKey
                    }),
                () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
            );
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update secure key failed: {ex.Message}"));
        }
    }

    private static async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> CreateMembershipAsync(
        EcliptixSchemaContext ctx, CreateMembershipActorEvent cmd)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead);
        try
        {
            const int attemptWindowHours = 1;
            const int maxAttempts = 5;

            VerificationFlowEntity? flow = await VerificationFlowQueries.GetByUniqueIdAndConnectionId(
                ctx, cmd.VerificationFlowIdentifier, cmd.ConnectId);

            if (flow?.MobileNumber == null)
            {
                await transaction.RollbackAsync();
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.CreateMembershipVerificationFlowNotFound));
            }

            Guid mobileUniqueId = flow.MobileNumber.UniqueId;
            string mobileNumber = flow.MobileNumber.Number;

            DateTime oneHourAgo = DateTime.UtcNow.AddHours(-attemptWindowHours);
            int failedAttempts = await LoginAttemptQueries.CountFailedMembershipCreationSince(ctx, mobileUniqueId, oneHourAgo);

            if (failedAttempts >= maxAttempts)
            {
                DateTime? earliestFailed = await LoginAttemptQueries.GetEarliestFailedMembershipCreationSince(ctx, mobileUniqueId, oneHourAgo);
                if (earliestFailed.HasValue)
                {
                    DateTime waitUntil = earliestFailed.Value.AddHours(attemptWindowHours);
                    int waitMinutes = (int)Math.Max(0, (waitUntil - DateTime.UtcNow).TotalMinutes);

                    LoginAttemptEntity rateLimitAttempt = new()
                    {
                        MembershipUniqueId = mobileUniqueId,
                        MobileNumber = mobileNumber,
                        Outcome = "membership_creation",
                        Status = "failed",
                        IsSuccess = false,
                        ErrorMessage = "rate_limit_exceeded",
                        AttemptedAt = DateTime.UtcNow,
                        Timestamp = DateTime.UtcNow
                    };
                    ctx.LoginAttempts.Add(rateLimitAttempt);
                    await ctx.SaveChangesAsync();

                    await transaction.RollbackAsync();
                    return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded(waitMinutes.ToString()));
                }
            }

            MembershipEntity? existingMembership = await MembershipQueries.GetByMobileUniqueIdAndDevice(
                ctx, mobileUniqueId, flow.AppDeviceId);

            if (existingMembership != null)
            {
                LoginAttemptEntity attempt = new()
                {
                    MembershipUniqueId = existingMembership.UniqueId,
                    MobileNumber = mobileNumber,
                    Outcome = "membership_creation",
                    Status = "failed",
                    IsSuccess = false,
                    ErrorMessage = "membership_already_exists",
                    AttemptedAt = DateTime.UtcNow,
                    Timestamp = DateTime.UtcNow
                };
                ctx.LoginAttempts.Add(attempt);
                await ctx.SaveChangesAsync();

                await transaction.RollbackAsync();

                return MapActivityStatus(existingMembership.Status).Match(
                    status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                        new MembershipQueryRecord
                        {
                            UniqueIdentifier = existingMembership.UniqueId,
                            ActivityStatus = status,
                            CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(existingMembership.CreationStatus ?? "otp_verified"),
                            CredentialsVersion = existingMembership.CredentialsVersion
                        }),
                    () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                );
            }

            MembershipEntity newMembership = new MembershipEntity
            {
                MobileNumberId = mobileUniqueId,
                AppDeviceId = flow.AppDeviceId,
                VerificationFlowId = flow.UniqueId,
                Status = "active",
                CreationStatus = MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus)
            };
            ctx.Memberships.Add(newMembership);
            await ctx.SaveChangesAsync();

            await ctx.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentifier && o.VerificationFlowId == flow.Id && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "used")
                    .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

            LoginAttemptEntity successAttempt = new LoginAttemptEntity
            {
                MembershipUniqueId = newMembership.UniqueId,
                MobileNumber = mobileNumber,
                Outcome = "membership_creation",
                Status = "success",
                IsSuccess = true,
                ErrorMessage = "created",
                AttemptedAt = DateTime.UtcNow,
                Timestamp = DateTime.UtcNow,
                SuccessfulAt = DateTime.UtcNow
            };
            ctx.LoginAttempts.Add(successAttempt);
            await ctx.SaveChangesAsync();

            List<long> failedAttemptIds = await ctx.LoginAttempts
                .Join(ctx.Memberships,
                    la => la.MembershipUniqueId,
                    m => m.UniqueId,
                    (la, m) => new { la, m })
                .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                            x.la.Outcome == "membership_creation" &&
                            x.la.Status == "failed" &&
                            !x.la.IsDeleted &&
                            !x.m.IsDeleted)
                .Select(x => x.la.Id)
                .ToListAsync();

            if (failedAttemptIds.Count > 0)
            {
                await ctx.LoginAttempts
                    .Where(la => failedAttemptIds.Contains(la.Id))
                    .ExecuteDeleteAsync();
            }

            await transaction.CommitAsync();

            return MapActivityStatus(newMembership.Status).Match(
                status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = newMembership.UniqueId,
                        ActivityStatus = status,
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(newMembership.CreationStatus),
                        CredentialsVersion = newMembership.CredentialsVersion
                    }),
                () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
            );
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Create membership failed: {ex.Message}"));
        }
    }


    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> GetMembershipByVerificationFlowAsync(
        EcliptixSchemaContext ctx, GetMembershipByVerificationFlowEvent cmd)
    {
        try
        {
            VerificationFlowEntity? verificationFlow = await ctx.VerificationFlows
                .Include(vf => vf.MobileNumber)
                .Where(vf => vf.UniqueId == cmd.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (verificationFlow == null)
            {
                Log.Warning("[GET-MEMBERSHIP-BY-FLOW] Verification flow not found: {FlowId}", cmd.VerificationFlowId);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Verification flow not found"));
            }

            MembershipEntity? membership;

            if (verificationFlow.Purpose == "password_recovery")
            {
                if (verificationFlow.MobileNumber == null)
                {
                    Log.Error("[GET-MEMBERSHIP-BY-FLOW] Mobile number not loaded for flow: {FlowId}", cmd.VerificationFlowId);
                    return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.NotFound("Mobile number not found for verification flow"));
                }

                membership = await ctx.Memberships
                    .Where(m => m.MobileNumberId == verificationFlow.MobileNumber.UniqueId &&
                                !m.IsDeleted)
                    .OrderByDescending(m => m.CreatedAt)
                    .FirstOrDefaultAsync();

                Log.Information("[GET-MEMBERSHIP-BY-FLOW] Password recovery - looking for membership by MobileNumberId: {MobileNumberId}, Found: {Found}",
                    verificationFlow.MobileNumber.UniqueId, membership != null);
            }
            else
            {
                membership = await ctx.Memberships
                    .Where(m => m.VerificationFlowId == cmd.VerificationFlowId &&
                                !m.IsDeleted)
                    .FirstOrDefaultAsync();

                Log.Information("[GET-MEMBERSHIP-BY-FLOW] {Purpose} - looking for membership by VerificationFlowId: {FlowId}, Found: {Found}",
                    verificationFlow.Purpose, cmd.VerificationFlowId, membership != null);
            }

            if (membership == null)
            {
                Log.Warning("[GET-MEMBERSHIP-BY-FLOW] Membership not found for flow: {FlowId}, Purpose: {Purpose}",
                    cmd.VerificationFlowId, verificationFlow.Purpose);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Membership not found for verification flow"));
            }

            Log.Information("[GET-MEMBERSHIP-BY-FLOW] Membership found: {MembershipId} for flow: {FlowId}",
                membership.UniqueId, cmd.VerificationFlowId);

            return MapActivityStatus(membership.Status).Match(
                status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = membership.UniqueId,
                        ActivityStatus = status,
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(membership.CreationStatus ?? "otp_verified"),
                        CredentialsVersion = membership.CredentialsVersion,
                        SecureKey = [],
                        MaskingKey = []
                    }),
                () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[GET-MEMBERSHIP-BY-FLOW] Exception while getting membership for flow: {FlowId}", cmd.VerificationFlowId);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Get membership by flow failed: {ex.Message}"));
        }
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> GetMembershipByUniqueIdAsync(
        EcliptixSchemaContext ctx, GetMembershipByUniqueIdEvent cmd)
    {
        try
        {
            MembershipEntity? membership = await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipUniqueId);

            if (membership == null)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Membership not found"));
            }

            return MapActivityStatus(membership.Status).Match(
                status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = membership.UniqueId,
                        ActivityStatus = status,
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(membership.CreationStatus ?? "otp_verified"),
                        CredentialsVersion = membership.CredentialsVersion,
                        SecureKey = membership.SecureKey ?? [],
                        MaskingKey = membership.MaskingKey ?? []
                    }),
                () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
            );
        }
        catch (Exception ex)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Get membership by unique ID failed: {ex.Message}"));
        }
    }

    private static Option<ProtoMembership.Types.ActivityStatus> MapActivityStatus(string? statusStr)
    {
        if (string.IsNullOrEmpty(statusStr) ||
            !MembershipStatusMap.TryGetValue(statusStr, out ProtoMembership.Types.ActivityStatus status))
            return Option<ProtoMembership.Types.ActivityStatus>.None;

        return Option<ProtoMembership.Types.ActivityStatus>.Some(status);
    }

    private async Task<Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>> ValidatePasswordRecoveryFlowAsync(
        EcliptixSchemaContext ctx, ValidatePasswordRecoveryFlowEvent cmd)
    {
        try
        {
            DateTime tenMinutesAgo = DateTime.UtcNow.AddMinutes(-10);

            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                Log.Warning("[PASSWORD-RECOVERY-VALIDATION] Membership not found: {MembershipId}", cmd.MembershipIdentifier);
                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            VerificationFlowEntity? recoveryFlow = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                            vf.Purpose == "password_recovery" &&
                            vf.Status == "verified" &&
                            vf.UpdatedAt >= tenMinutesAgo &&
                            !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (recoveryFlow == null)
            {
                VerificationFlowEntity? existingFlow = await ctx.VerificationFlows
                    .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                    .FirstOrDefaultAsync();

                if (existingFlow != null)
                {
                    TimeSpan elapsed = DateTime.UtcNow - existingFlow.UpdatedAt;
                    Log.Warning("[PASSWORD-RECOVERY-VALIDATION] Recovery flow invalid. MembershipId: {MembershipId}, FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}, ElapsedMinutes: {Minutes}",
                        cmd.MembershipIdentifier, existingFlow.UniqueId, existingFlow.Purpose, existingFlow.Status, elapsed.TotalMinutes);
                }
                else
                {
                    Log.Warning("[PASSWORD-RECOVERY-VALIDATION] No verification flow found for membership: {MembershipId}, ExpectedFlowId: {FlowId}",
                        cmd.MembershipIdentifier, membership.VerificationFlowId);
                }

                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            Log.Information("[PASSWORD-RECOVERY-VALIDATION] Valid recovery flow found. MembershipId: {MembershipId}, FlowId: {FlowId}",
                cmd.MembershipIdentifier, recoveryFlow.UniqueId);

            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                new PasswordRecoveryFlowValidation(true, recoveryFlow.UniqueId));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[PASSWORD-RECOVERY-VALIDATION] Exception during validation for MembershipId: {MembershipId}", cmd.MembershipIdentifier);
            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Validate password recovery flow failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> ExpirePasswordRecoveryFlowsAsync(
        EcliptixSchemaContext ctx, ExpirePasswordRecoveryFlowsEvent cmd)
    {
        try
        {
            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                Log.Warning("[PASSWORD-RECOVERY-EXPIRE] Membership not found: {MembershipId}", cmd.MembershipIdentifier);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            int rowsAffected = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                            vf.Purpose == "password_recovery" &&
                            vf.Status == "verified" &&
                            !vf.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(vf => vf.Status, "expired")
                    .SetProperty(vf => vf.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected > 0)
            {
                Log.Information("[PASSWORD-RECOVERY-EXPIRE] Expired {Count} recovery flow(s) for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    rowsAffected, cmd.MembershipIdentifier, membership.VerificationFlowId);
            }
            else
            {
                Log.Warning("[PASSWORD-RECOVERY-EXPIRE] No verified recovery flows to expire for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    cmd.MembershipIdentifier, membership.VerificationFlowId);
            }

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[PASSWORD-RECOVERY-EXPIRE] Exception while expiring flows for MembershipId: {MembershipId}", cmd.MembershipIdentifier);
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Expire password recovery flows failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateMembershipVerificationFlowAsync(
        EcliptixSchemaContext ctx, UpdateMembershipVerificationFlowEvent cmd)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
        try
        {
            if (cmd.Purpose != "password_recovery" || cmd.FlowStatus != "verified")
            {
                await transaction.RollbackAsync();
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Skipping update - Purpose: {Purpose}, Status: {Status}. Only password_recovery + verified are processed",
                    cmd.Purpose, cmd.FlowStatus);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            VerificationFlowEntity? newFlow = await ctx.VerificationFlows
                .Include(vf => vf.MobileNumber)
                .Where(vf => vf.UniqueId == cmd.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (newFlow?.MobileNumber == null)
            {
                await transaction.RollbackAsync();
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Verification flow or mobile number not found: {FlowId}", cmd.VerificationFlowId);
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Verification flow or mobile number not found"));
            }

            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.MobileNumberId == newFlow.MobileNumber.UniqueId && !m.IsDeleted)
                .OrderByDescending(m => m.CreatedAt)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                await transaction.RollbackAsync();
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Membership not found for MobileNumberId: {MobileNumberId}", newFlow.MobileNumber.UniqueId);
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Membership not found"));
            }

            VerificationFlowEntity? currentFlow = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (currentFlow != null && currentFlow.UpdatedAt >= newFlow.UpdatedAt)
            {
                await transaction.RollbackAsync();
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Skipping update - current flow {CurrentFlowId} (updated: {CurrentUpdated}) is newer than or equal to new flow {NewFlowId} (updated: {NewUpdated})",
                    currentFlow.UniqueId, currentFlow.UpdatedAt, newFlow.UniqueId, newFlow.UpdatedAt);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            Guid oldFlowId = membership.VerificationFlowId;

            int rowsAffected = await ctx.Memberships
                .Where(m => m.UniqueId == membership.UniqueId &&
                           m.VerificationFlowId == oldFlowId &&
                           !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.VerificationFlowId, newFlow.UniqueId)
                    .SetProperty(m => m.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
            {
                await transaction.RollbackAsync();
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Optimistic concurrency failure - membership {MembershipId} was modified by another transaction",
                    membership.UniqueId);
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.ConcurrencyConflict("Membership was modified by another transaction"));
            }

            await transaction.CommitAsync();

            Log.Information("[UPDATE-MEMBERSHIP-FLOW] ✅ Successfully updated membership {MembershipId} VerificationFlowId: {OldFlowId} → {NewFlowId} (Purpose: {Purpose}, CurrentFlowUpdated: {CurrentUpdated}, NewFlowUpdated: {NewUpdated})",
                membership.UniqueId, oldFlowId, newFlow.UniqueId, cmd.Purpose,
                currentFlow?.UpdatedAt.ToString("O") ?? "null", newFlow.UpdatedAt.ToString("O"));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            Log.Error(ex, "[UPDATE-MEMBERSHIP-FLOW] Exception while updating membership verification flow for FlowId: {FlowId}", cmd.VerificationFlowId);
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update membership verification flow failed: {ex.Message}"));
        }
    }

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict(
                    $"Unique constraint violation: {sqlEx.Message}"),
                547 => VerificationFlowFailure.Validation($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => VerificationFlowFailure.ConcurrencyConflict($"Deadlock detected: {sqlEx.Message}"),
                -2 => VerificationFlowFailure.PersistorAccess("Command timeout occurred", sqlEx),
                2 => VerificationFlowFailure.PersistorAccess("Network error occurred", sqlEx),
                18456 => VerificationFlowFailure.PersistorAccess("Authentication failed", sqlEx),
                _ => VerificationFlowFailure.PersistorAccess($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}",
                    sqlEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess("Database operation failed", ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return VerificationFlowFailure.PersistorAccess("Database operation timed out", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        return VerificationFlowFailure.Generic($"Unexpected error in membership persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}