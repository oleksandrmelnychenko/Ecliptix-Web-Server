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

        Receive<ValidatePasswordRecoveryFlowEvent>(cmd =>
            ExecuteWithContext(ctx => ValidatePasswordRecoveryFlowAsync(ctx, cmd), "ValidatePasswordRecoveryFlow")
                .PipeTo(Sender));

        Receive<ExpirePasswordRecoveryFlowsEvent>(cmd =>
            ExecuteWithContext(ctx => ExpirePasswordRecoveryFlowsAsync(ctx, cmd), "ExpirePasswordRecoveryFlows")
                .PipeTo(Sender));
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> SignInMembershipAsync(
        EcliptixSchemaContext ctx, SignInMembershipActorEvent cmd)
    {
        const int lockoutDurationMinutes = 5;
        const int maxAttemptsInPeriod = 5;

        try
        {
            DateTime currentTime = DateTime.UtcNow;

            LoginAttempt? lockoutMarker = await LoginAttemptQueries.GetMostRecentLockout(ctx, cmd.MobileNumber);
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
                LoginAttempt lockoutAttempt = new()
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

            Membership? membership = await MembershipQueries.GetByMobileNumber(ctx, cmd.MobileNumber);
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
        LoginAttempt attempt = new LoginAttempt
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

            Membership? membership = await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipIdentifier);
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
                    .SetProperty(m => m.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
            {
                await transaction.RollbackAsync();
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess("Failed to update membership"));
            }

            await transaction.CommitAsync();

            return MapActivityStatus("active").Match(
                status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = cmd.MembershipIdentifier,
                        ActivityStatus = status,
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum("secure_key_set"),
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

            VerificationFlow? flow = await VerificationFlowQueries.GetByUniqueIdAndConnectionId(
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

                    LoginAttempt rateLimitAttempt = new()
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

            Membership? existingMembership = await MembershipQueries.GetByMobileUniqueIdAndDevice(
                ctx, mobileUniqueId, flow.AppDeviceId);

            if (existingMembership != null)
            {
                LoginAttempt attempt = new()
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
                            CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(existingMembership.CreationStatus ?? "otp_verified")
                        }),
                    () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
                );
            }

            Membership newMembership = new Membership
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

            LoginAttempt successAttempt = new LoginAttempt
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
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(newMembership.CreationStatus)
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
            VerificationFlow? verificationFlow = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == cmd.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (verificationFlow == null)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Verification flow not found"));
            }

            Membership? membership;

            if (verificationFlow.Purpose == "password_recovery")
            {
                membership = await ctx.Memberships
                    .Join(ctx.MobileNumbers,
                        m => m.MobileNumberId,
                        mn => mn.UniqueId,
                        (m, mn) => new { Membership = m, MobileNumber = mn })
                    .Where(x => x.MobileNumber.Id == verificationFlow.MobileNumberId &&
                                x.Membership.AppDeviceId == verificationFlow.AppDeviceId &&
                                !x.Membership.IsDeleted)
                    .Select(x => x.Membership)
                    .OrderByDescending(m => m.CreatedAt)
                    .FirstOrDefaultAsync();
            }
            else
            {
                membership = await ctx.Memberships
                    .Where(m => m.VerificationFlowId == cmd.VerificationFlowId &&
                                !m.IsDeleted)
                    .FirstOrDefaultAsync();
            }

            if (membership == null)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Membership not found for verification flow"));
            }

            return MapActivityStatus(membership.Status).Match(
                status => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                    new MembershipQueryRecord
                    {
                        UniqueIdentifier = membership.UniqueId,
                        ActivityStatus = status,
                        CreationStatus = MembershipCreationStatusHelper.GetCreationStatusEnum(membership.CreationStatus ?? "otp_verified"),
                        SecureKey = [],
                        MaskingKey = []
                    }),
                () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
            );
        }
        catch (Exception ex)
        {
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Get membership by flow failed: {ex.Message}"));
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

            Membership? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            VerificationFlow? recoveryFlow = await ctx.VerificationFlows
                .Join(ctx.MobileNumbers,
                    vf => vf.MobileNumberId,
                    mn => mn.Id,
                    (vf, mn) => new { VerificationFlow = vf, MobileNumber = mn })
                .Where(x => x.MobileNumber.UniqueId == membership.MobileNumberId &&
                            x.VerificationFlow.Purpose == "password_recovery" &&
                            x.VerificationFlow.Status == "verified" &&
                            x.VerificationFlow.UpdatedAt >= tenMinutesAgo &&
                            !x.VerificationFlow.IsDeleted)
                .Select(x => x.VerificationFlow)
                .OrderByDescending(vf => vf.UpdatedAt)
                .FirstOrDefaultAsync();

            if (recoveryFlow == null)
            {
                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                new PasswordRecoveryFlowValidation(true, recoveryFlow.UniqueId));
        }
        catch (Exception ex)
        {
            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Validate password recovery flow failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> ExpirePasswordRecoveryFlowsAsync(
        EcliptixSchemaContext ctx, ExpirePasswordRecoveryFlowsEvent cmd)
    {
        try
        {
            Membership? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            int rowsAffected = await ctx.VerificationFlows
                .Join(ctx.MobileNumbers,
                    vf => vf.MobileNumberId,
                    mn => mn.Id,
                    (vf, mn) => new { VerificationFlow = vf, MobileNumber = mn })
                .Where(x => x.MobileNumber.UniqueId == membership.MobileNumberId &&
                            x.VerificationFlow.Purpose == "password_recovery" &&
                            x.VerificationFlow.Status == "verified" &&
                            !x.VerificationFlow.IsDeleted)
                .Select(x => x.VerificationFlow)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(vf => vf.Status, "expired")
                    .SetProperty(vf => vf.UpdatedAt, DateTime.UtcNow));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Expire password recovery flows failed: {ex.Message}"));
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