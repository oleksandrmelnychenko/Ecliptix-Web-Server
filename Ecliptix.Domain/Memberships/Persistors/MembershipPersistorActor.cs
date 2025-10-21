using System.Collections.Frozen;
using System.Data.Common;
using System.Linq;
using System.Threading;
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
    private static readonly FrozenDictionary<string, ProtoMembership.Types.ActivityStatus> MembershipStatusMap =
        new Dictionary<string, ProtoMembership.Types.ActivityStatus>
        {
            ["active"] = ProtoMembership.Types.ActivityStatus.Active,
            ["inactive"] = ProtoMembership.Types.ActivityStatus.Inactive
        }.ToFrozenDictionary();

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
        RegisterHandlers();

        ReceiveAsync<UpdateMembershipVerificationFlowEvent>(async cmd =>
        {
            Log.Information(
                "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Received UpdateMembershipVerificationFlowEvent for FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}",
                cmd.VerificationFlowId, cmd.Purpose, cmd.FlowStatus);

            Result<Unit, VerificationFlowFailure> result = await ExecuteWithContext(
                (ctx, ct) => UpdateMembershipVerificationFlowAsync(ctx, cmd, ct),
                "UpdateMembershipVerificationFlow");

            result.Match<Unit>(
                ok =>
                {
                    Log.Information(
                        "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Successfully processed event for FlowId: {FlowId}",
                        cmd.VerificationFlowId);
                    return Unit.Value;
                },
                err =>
                {
                    Log.Error(
                        "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Failed to process event for FlowId: {FlowId}, Error: {Error}",
                        cmd.VerificationFlowId, err.Message);
                    return Unit.Value;
                }
            );

            Sender.Tell(result);
        });
    }

    private void RegisterHandlers()
    {
        ReceivePersistorCommand<UpdateMembershipSecureKeyEvent, MembershipQueryRecord>(
            UpdateMembershipSecureKeyAsync,
            "UpdateMembershipSecureKey");

        ReceivePersistorCommand<CreateMembershipActorEvent, MembershipQueryRecord>(
            CreateMembershipAsync,
            "CreateMembership");

        ReceivePersistorCommand<SignInMembershipActorEvent, MembershipQueryRecord>(
            SignInMembershipAsync,
            "LoginMembership");

        ReceivePersistorCommand<GetMembershipByVerificationFlowEvent, MembershipQueryRecord>(
            GetMembershipByVerificationFlowAsync,
            "GetMembershipByVerificationFlow");

        ReceivePersistorCommand<GetMembershipByUniqueIdEvent, MembershipQueryRecord>(
            GetMembershipByUniqueIdAsync,
            "GetMembershipByUniqueId");

        ReceivePersistorCommand<CreateDefaultAccountEvent, AccountCreationResult>(
            CreateDefaultAccountAsync,
            "CreateDefaultAccount");

        ReceivePersistorCommand<ValidatePasswordRecoveryFlowEvent, PasswordRecoveryFlowValidation>(
            ValidatePasswordRecoveryFlowAsync,
            "ValidatePasswordRecoveryFlow");

        ReceivePersistorCommand<ExpirePasswordRecoveryFlowsEvent, Unit>(
            ExpirePasswordRecoveryFlowsAsync,
            "ExpirePasswordRecoveryFlows");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, VerificationFlowFailure>>> handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            Task<Result<TResult, VerificationFlowFailure>> Operation(EcliptixSchemaContext ctx, CancellationToken ct)
            {
                CancellationToken effectiveToken = CombineCancellationTokens(ct, messageToken, out CancellationTokenSource? linkedCts);
                try
                {
                    return handler(ctx, message, effectiveToken);
                }
                finally
                {
                    linkedCts?.Dispose();
                }
            }

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);
        });
    }

    private static CancellationToken ExtractCancellationToken(object? message)
    {
        return message is ICancellableActorEvent cancellable ? cancellable.CancellationToken : CancellationToken.None;
    }

    private static CancellationToken CombineCancellationTokens(
        CancellationToken first,
        CancellationToken second,
        out CancellationTokenSource? linkedSource)
    {
        linkedSource = null;

        bool firstActive = first.CanBeCanceled;
        bool secondActive = second.CanBeCanceled;

        switch (firstActive)
        {
            case false when !secondActive:
                return CancellationToken.None;
            case false:
                return second;
        }

        if (!secondActive)
        {
            return first;
        }

        linkedSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedSource.Token;
    }

    private static Task RollbackSilentlyAsync(IDbContextTransaction transaction)
    {
        return transaction.RollbackAsync(CancellationToken.None);
    }

    private static Result<MembershipQueryRecord, VerificationFlowFailure> BuildMembershipResult(
        Guid membershipId,
        string status,
        ProtoMembership.Types.CreationStatus creationStatus,
        int credentialsVersion,
        IEnumerable<AccountInfo>? accounts = null,
        Guid? activeAccountId = null,
        byte[]? secureKey = null,
        byte[]? maskingKey = null)
    {
        return MapActivityStatus(status).Match(
            activityStatus => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(
                new MembershipQueryRecord
                {
                    UniqueIdentifier = membershipId,
                    ActivityStatus = activityStatus,
                    CreationStatus = creationStatus,
                    CredentialsVersion = credentialsVersion,
                    SecureKey = secureKey ?? [],
                    MaskingKey = maskingKey ?? [],
                    AvailableAccounts = MaterializeAccounts(accounts),
                    ActiveAccountId = activeAccountId
                }),
            () => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess(VerificationFlowMessageKeys.ActivityStatusInvalid))
        );
    }

    private static List<AccountInfo> MaterializeAccounts(IEnumerable<AccountInfo>? accounts)
    {
        return accounts switch
        {
            null => new List<AccountInfo>(),
            List<AccountInfo> list => list,
            _ => accounts.ToList()
        };
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> SignInMembershipAsync(
        EcliptixSchemaContext ctx,
        SignInMembershipActorEvent cmd,
        CancellationToken cancellationToken)
    {
        const int lockoutDurationMinutes = 5;
        const int maxAttemptsInPeriod = 5;

        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            Option<LoginAttemptEntity> lockoutMarkerOpt =
                await LoginAttemptQueries.GetMostRecentLockout(ctx, cmd.MobileNumber, cancellationToken);
            if (lockoutMarkerOpt.HasValue && lockoutMarkerOpt.Value!.LockedUntil != null)
            {
                LoginAttemptEntity lockoutMarker = lockoutMarkerOpt.Value!;
                if (now < lockoutMarker.LockedUntil!.Value)
                {
                    int remainingMinutes = (int)Math.Ceiling((lockoutMarker.LockedUntil!.Value - now).TotalMinutes);
                    await RollbackSilentlyAsync(transaction);
                    return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded(remainingMinutes.ToString()));
                }

                await ctx.LoginAttempts
                    .Where(la => la.MobileNumber == cmd.MobileNumber &&
                                 la.AttemptedAt <= lockoutMarker.AttemptedAt &&
                                 !la.IsDeleted)
                    .ExecuteDeleteAsync(cancellationToken);
            }

            DateTimeOffset fiveMinutesAgo = now.AddMinutes(-5);
            int failedCount =
                await LoginAttemptQueries.CountFailedSince(ctx, cmd.MobileNumber, fiveMinutesAgo, cancellationToken);

            if (failedCount >= maxAttemptsInPeriod)
            {
                DateTimeOffset lockedUntil = now.AddMinutes(lockoutDurationMinutes);
                LoginAttemptEntity lockoutAttempt = new()
                {
                    MobileNumber = cmd.MobileNumber,
                    LockedUntil = lockedUntil,
                    Outcome = "rate_limit_exceeded",
                    IsSuccess = false,
                    AttemptedAt = now,
                    IpAddress = null,
                    Platform = null
                };
                ctx.LoginAttempts.Add(lockoutAttempt);
                await ctx.SaveChangesAsync(cancellationToken);

                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded(lockoutDurationMinutes.ToString()));
            }

            if (string.IsNullOrEmpty(cmd.MobileNumber))
            {
                LogLoginAttempt(ctx, cmd.MobileNumber, "mobile_number_cannot_be_empty", false, now);
                await ctx.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.MobileNumberCannotBeEmpty));
            }

            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByMobileNumber(ctx, cmd.MobileNumber, cancellationToken);
            if (!membershipOpt.HasValue)
            {
                LogLoginAttempt(ctx, cmd.MobileNumber, "mobile_number_not_found", false, now);
                await ctx.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.MobileNotFound));
            }

            MembershipEntity membership = membershipOpt.Value!;

            if (membership.SecureKey == null || membership.SecureKey.Length == 0)
            {
                LogLoginAttempt(ctx, cmd.MobileNumber, "secure_key_not_set", false, now);
                await ctx.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.SecureKeyNotSet));
            }

            if (membership.Status != "active")
            {
                LogLoginAttempt(ctx, cmd.MobileNumber, "inactive_membership", false, now);
                await ctx.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys.InactiveMembership));
            }

            LogLoginAttempt(ctx, cmd.MobileNumber, "success", true, now, membershipId: membership.UniqueId);

            await ctx.LoginAttempts
                .Where(la => la.MobileNumber == cmd.MobileNumber &&
                             (!la.IsSuccess || la.LockedUntil != null) &&
                             !la.IsDeleted)
                .ExecuteDeleteAsync(cancellationToken);

            List<AccountInfo> accounts =
                await AccountQueries.GetAccountsByMembershipId(ctx, membership.UniqueId, cancellationToken);

            DeviceContextEntity? deviceContext = await ctx.DeviceContexts
                .Where(dc => dc.MembershipId == membership.UniqueId &&
                             dc.DeviceId == cmd.DeviceId &&
                             dc.IsActive &&
                             !dc.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            bool createdDeviceContext = false;
            DeviceContextEntity? pendingDeviceContext = null;

            if (deviceContext == null)
            {
                bool deviceExists = await ctx.Devices
                    .Where(d => d.UniqueId == cmd.DeviceId && !d.IsDeleted)
                    .AnyAsync(cancellationToken);

                if (deviceExists)
                {
                    AccountInfo? defaultAccount = accounts.FirstOrDefault(a => a.IsDefault);
                    if (defaultAccount != null)
                    {
                        pendingDeviceContext = new DeviceContextEntity
                        {
                            MembershipId = membership.UniqueId,
                            DeviceId = cmd.DeviceId,
                            ActiveAccountId = defaultAccount.AccountId,
                            ContextEstablishedAt = now,
                            ContextExpiresAt = now.AddDays(30),
                            LastActivityAt = now,
                            IsActive = true
                        };
                        ctx.DeviceContexts.Add(pendingDeviceContext);
                        createdDeviceContext = true;
                        deviceContext = pendingDeviceContext;
                    }
                }
                else
                {
                    Log.Warning(
                        "[SIGN-IN] Device {DeviceId} not found, skipping device context creation. Membership: {MembershipId}",
                        cmd.DeviceId, membership.UniqueId);
                }
            }

            try
            {
                await ctx.SaveChangesAsync(cancellationToken);

                if (createdDeviceContext && deviceContext != null)
                {
                    Log.Information(
                        "[SIGN-IN] Created device context for Device: {DeviceId}, Membership: {MembershipId}",
                        cmd.DeviceId, membership.UniqueId);
                }
            }
            catch (DbUpdateException dbEx) when (createdDeviceContext &&
                                                 pendingDeviceContext != null &&
                                                 dbEx.InnerException is SqlException sqlEx &&
                                                 sqlEx.Number == 547)
            {
                Log.Warning(
                    "[SIGN-IN] Foreign key constraint violation creating device context. Device {DeviceId} may have been deleted. Membership: {MembershipId}. Error: {Error}",
                    cmd.DeviceId, membership.UniqueId, sqlEx.Message);

                ctx.Entry(pendingDeviceContext).State = EntityState.Detached;
                deviceContext = null;
                await ctx.SaveChangesAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.Status,
                ProtoMembership.Types.CreationStatus.OtpVerified,
                membership.CredentialsVersion,
                accounts,
                deviceContext?.ActiveAccountId,
                membership.SecureKey,
                membership.MaskingKey);
        }
        catch (OperationCanceledException)
        {
            await RollbackSilentlyAsync(transaction);
            throw;
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Login failed: {ex.Message}"));
        }
    }

    private static void LogLoginAttempt(EcliptixSchemaContext ctx, string mobileNumber, string outcome, bool isSuccess,
        DateTimeOffset timestamp, Guid? membershipId = null, string? ipAddress = null, string? platform = null)
    {
        LoginAttemptEntity attempt = new()
        {
            MembershipUniqueId = membershipId,
            MobileNumber = mobileNumber,
            Outcome = outcome,
            IsSuccess = isSuccess,
            AttemptedAt = timestamp,
            CompletedAt = isSuccess ? timestamp : null,
            IpAddress = ipAddress,
            Platform = platform
        };
        ctx.LoginAttempts.Add(attempt);
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> UpdateMembershipSecureKeyAsync(
        EcliptixSchemaContext ctx, UpdateMembershipSecureKeyEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
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

            Option<MembershipEntity> membershipOpt = await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipIdentifier, cancellationToken);
            if (!membershipOpt.HasValue)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("Membership not found or deleted"));
            }

            MembershipEntity membership = membershipOpt.Value!;

            int rowsAffected = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.SecureKey, cmd.SecureKey)
                    .SetProperty(m => m.MaskingKey, cmd.MaskingKey)
                    .SetProperty(m => m.Status, "active")
                    .SetProperty(m => m.CreationStatus, "secure_key_set")
                    .SetProperty(m => m.CredentialsVersion, m => m.CredentialsVersion + 1)
                    .SetProperty(m => m.UpdatedAt, DateTimeOffset.UtcNow));

            if (rowsAffected == 0)
            {
                await transaction.RollbackAsync(cancellationToken);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.PersistorAccess("Failed to update membership"));
            }

            await transaction.CommitAsync(cancellationToken);

            int newCredentialsVersion = membership.CredentialsVersion + 1;

            ProtoMembership.Types.CreationStatus creationStatus =
                MembershipCreationStatusHelper.GetCreationStatusEnum("secure_key_set");

            return BuildMembershipResult(
                cmd.MembershipIdentifier,
                "active",
                creationStatus,
                newCredentialsVersion,
                maskingKey: cmd.MaskingKey);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update secure key failed: {ex.Message}"));
        }
    }

    private static async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> CreateMembershipAsync(
        EcliptixSchemaContext ctx, CreateMembershipActorEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, cancellationToken);
        try
        {
            const int attemptWindowHours = 1;
            const int maxAttempts = 5;

            Option<VerificationFlowEntity> flowOpt = await VerificationFlowQueries.GetByUniqueIdAndConnectionId(
                ctx, cmd.VerificationFlowIdentifier, cmd.ConnectId, cancellationToken);

            if (!flowOpt.HasValue || flowOpt.Value!.MobileNumber == null)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation(VerificationFlowMessageKeys
                        .CreateMembershipVerificationFlowNotFound));
            }

            VerificationFlowEntity flow = flowOpt.Value!;

            Guid mobileUniqueId = flow.MobileNumber.UniqueId;
            string mobileNumber = flow.MobileNumber.Number;

            DateTimeOffset oneHourAgo = DateTimeOffset.UtcNow.AddHours(-attemptWindowHours);
            int failedAttempts =
                await LoginAttemptQueries.CountFailedMembershipCreationSince(ctx, mobileUniqueId, oneHourAgo,
                    cancellationToken);

            if (failedAttempts >= maxAttempts)
            {
                DateTimeOffset? earliestFailed =
                    await LoginAttemptQueries.GetEarliestFailedMembershipCreationSince(ctx, mobileUniqueId, oneHourAgo,
                        cancellationToken);
                if (earliestFailed.HasValue)
                {
                    DateTimeOffset waitUntil = earliestFailed.Value!.AddHours(attemptWindowHours);
                    int waitMinutes = (int)Math.Max(0, (waitUntil - DateTimeOffset.UtcNow).TotalMinutes);

                    LoginAttemptEntity rateLimitAttempt = new()
                    {
                        MembershipUniqueId = mobileUniqueId,
                        MobileNumber = mobileNumber,
                        Outcome = "membership_creation",
                        IsSuccess = false,
                        ErrorMessage = "rate_limit_exceeded",
                        AttemptedAt = DateTimeOffset.UtcNow,
                        IpAddress = null,
                        Platform = null
                    };
                    ctx.LoginAttempts.Add(rateLimitAttempt);
                    await ctx.SaveChangesAsync(cancellationToken);

                    await RollbackSilentlyAsync(transaction);
                    return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.RateLimitExceeded(waitMinutes.ToString()));
                }
            }

            Option<MembershipEntity> existingMembershipOpt = await MembershipQueries.GetByMobileUniqueIdAndDevice(
                ctx, mobileUniqueId, flow.AppDeviceId, cancellationToken);

            if (existingMembershipOpt.HasValue)
            {
                MembershipEntity existingMembership = existingMembershipOpt.Value!;
                LoginAttemptEntity attempt = new()
                {
                    MembershipUniqueId = existingMembership.UniqueId,
                    MobileNumber = mobileNumber,
                    Outcome = "membership_creation",
                    IsSuccess = false,
                    ErrorMessage = "membership_already_exists",
                    AttemptedAt = DateTimeOffset.UtcNow,
                    IpAddress = null,
                    Platform = null
                };
                ctx.LoginAttempts.Add(attempt);
                await ctx.SaveChangesAsync(cancellationToken);

                await RollbackSilentlyAsync(transaction);

                string existingCreationStatusString = existingMembership.CreationStatus ?? "otp_verified";
                ProtoMembership.Types.CreationStatus existingCreationStatus =
                    MembershipCreationStatusHelper.GetCreationStatusEnum(existingCreationStatusString);

                return BuildMembershipResult(
                    existingMembership.UniqueId,
                    existingMembership.Status,
                    existingCreationStatus,
                    existingMembership.CredentialsVersion);
            }

            MembershipEntity newMembership = new()
            {
                MobileNumberId = mobileUniqueId,
                AppDeviceId = flow.AppDeviceId,
                VerificationFlowId = flow.UniqueId,
                Status = "active",
                CreationStatus = MembershipCreationStatusHelper.GetCreationStatusString(cmd.CreationStatus)
            };
            ctx.Memberships.Add(newMembership);
            await ctx.SaveChangesAsync(cancellationToken);

            await ctx.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentifier && o.VerificationFlowId == flow.Id && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "used")
                    .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

            LoginAttemptEntity successAttempt = new()
            {
                MembershipUniqueId = newMembership.UniqueId,
                MobileNumber = mobileNumber,
                Outcome = "membership_creation",
                IsSuccess = true,
                ErrorMessage = "created",
                AttemptedAt = DateTimeOffset.UtcNow,
                CompletedAt = DateTimeOffset.UtcNow,
                IpAddress = null,
                Platform = null
            };
            ctx.LoginAttempts.Add(successAttempt);
            await ctx.SaveChangesAsync(cancellationToken);

            List<long> failedAttemptIds = await ctx.LoginAttempts
                .Join(ctx.Memberships,
                    la => la.MembershipUniqueId,
                    m => m.UniqueId,
                    (la, m) => new { la, m })
                .Where(x => x.m.MobileNumberId == mobileUniqueId &&
                            x.la.Outcome == "membership_creation" &&
                            !x.la.IsSuccess &&
                            !x.la.IsDeleted &&
                            !x.m.IsDeleted)
                .Select(x => x.la.Id)
                .ToListAsync(cancellationToken);

            if (failedAttemptIds.Count > 0)
            {
                await ctx.LoginAttempts
                    .Where(la => failedAttemptIds.Contains(la.Id))
                    .ExecuteDeleteAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            ProtoMembership.Types.CreationStatus newMembershipCreationStatus =
                MembershipCreationStatusHelper.GetCreationStatusEnum(newMembership.CreationStatus);

            return BuildMembershipResult(
                newMembership.UniqueId,
                newMembership.Status,
                newMembershipCreationStatus,
                newMembership.CredentialsVersion);
        }
        catch (OperationCanceledException)
        {
            await RollbackSilentlyAsync(transaction);
            throw;
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Create membership failed: {ex.Message}"));
        }
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> GetMembershipByVerificationFlowAsync(
        EcliptixSchemaContext ctx,
        GetMembershipByVerificationFlowEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            VerificationFlowEntity? verificationFlow = await ctx.VerificationFlows
                .Include(vf => vf.MobileNumber)
                .Where(vf => vf.UniqueId == cmd.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

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
                    Log.Error("[GET-MEMBERSHIP-BY-FLOW] Mobile number not loaded for flow: {FlowId}",
                        cmd.VerificationFlowId);
                    return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                        VerificationFlowFailure.NotFound("Mobile number not found for verification flow"));
                }

                membership = await ctx.Memberships
                    .Where(m => m.MobileNumberId == verificationFlow.MobileNumber.UniqueId &&
                                !m.IsDeleted)
                    .OrderByDescending(m => m.CreatedAt)
                    .FirstOrDefaultAsync(cancellationToken);

                Log.Information(
                    "[GET-MEMBERSHIP-BY-FLOW] Password recovery - looking for membership by MobileNumberId: {MobileNumberId}, Found: {Found}",
                    verificationFlow.MobileNumber.UniqueId, membership != null);
            }
            else
            {
                membership = await ctx.Memberships
                    .Where(m => m.VerificationFlowId == cmd.VerificationFlowId &&
                                !m.IsDeleted)
                    .FirstOrDefaultAsync(cancellationToken);

                Log.Information(
                    "[GET-MEMBERSHIP-BY-FLOW] {Purpose} - looking for membership by VerificationFlowId: {FlowId}, Found: {Found}",
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

            string creationStatusString = membership.CreationStatus ?? "otp_verified";
            ProtoMembership.Types.CreationStatus creationStatus =
                MembershipCreationStatusHelper.GetCreationStatusEnum(creationStatusString);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.Status,
                creationStatus,
                membership.CredentialsVersion);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[GET-MEMBERSHIP-BY-FLOW] Exception while getting membership for flow: {FlowId}",
                cmd.VerificationFlowId);
            return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Get membership by flow failed: {ex.Message}"));
        }
    }

    private async Task<Result<MembershipQueryRecord, VerificationFlowFailure>> GetMembershipByUniqueIdAsync(
        EcliptixSchemaContext ctx,
        GetMembershipByUniqueIdEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MembershipEntity> membershipOpt = await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipUniqueId, cancellationToken);

            if (!membershipOpt.HasValue)
            {
                return Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Membership not found"));
            }

            MembershipEntity membership = membershipOpt.Value!;

            string creationStatusString = membership.CreationStatus ?? "otp_verified";
            ProtoMembership.Types.CreationStatus creationStatus =
                MembershipCreationStatusHelper.GetCreationStatusEnum(creationStatusString);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.Status,
                creationStatus,
                membership.CredentialsVersion,
                secureKey: membership.SecureKey,
                maskingKey: membership.MaskingKey);
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
        {
            return Option<ProtoMembership.Types.ActivityStatus>.None;
        }

        return Option<ProtoMembership.Types.ActivityStatus>.Some(status);
    }

    private async Task<Result<AccountCreationResult, VerificationFlowFailure>> CreateDefaultAccountAsync(
        EcliptixSchemaContext ctx, CreateDefaultAccountEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            AccountEntity personalAccount = new()
            {
                MembershipId = cmd.MembershipId,
                AccountType = Protobuf.Account.AccountType.Personal,
                AccountName = "Personal",
                Status = Protobuf.Account.AccountStatus.Active,
                IsDefaultAccount = true,
                CredentialsVersion = 1
            };

            ctx.Accounts.Add(personalAccount);
            await ctx.SaveChangesAsync(cancellationToken);

            List<AccountInfo> accounts =
            [
                new(
                    personalAccount.UniqueId,
                    cmd.MembershipId,
                    Protobuf.Account.AccountType.Personal,
                    "Personal",
                    true,
                    Protobuf.Account.AccountStatus.Active)
            ];

            await transaction.CommitAsync(cancellationToken);
            return Result<AccountCreationResult, VerificationFlowFailure>.Ok(
                new AccountCreationResult(accounts, accounts[0]));
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex, "Failed to create default account for MembershipId: {MembershipId}", cmd.MembershipId);
            return Result<AccountCreationResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Failed to create default account: {ex.Message}"));
        }
    }

    private async Task<Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>>
        ValidatePasswordRecoveryFlowAsync(
            EcliptixSchemaContext ctx,
            ValidatePasswordRecoveryFlowEvent cmd,
            CancellationToken cancellationToken)
    {
        try
        {
            DateTimeOffset tenMinutesAgo = DateTimeOffset.UtcNow.AddMinutes(-10);

            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (membership == null)
            {
                Log.Warning("[PASSWORD-RECOVERY-VALIDATION] Membership not found: {MembershipId}",
                    cmd.MembershipIdentifier);
                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            VerificationFlowEntity? recoveryFlow = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                             vf.Purpose == "password_recovery" &&
                             vf.Status == "verified" &&
                             vf.UpdatedAt >= tenMinutesAgo &&
                             !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (recoveryFlow == null)
            {
                VerificationFlowEntity? existingFlow = await ctx.VerificationFlows
                    .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                    .FirstOrDefaultAsync(cancellationToken);

                if (existingFlow != null)
                {
                    TimeSpan elapsed = DateTimeOffset.UtcNow - existingFlow.UpdatedAt;
                    Log.Warning(
                        "[PASSWORD-RECOVERY-VALIDATION] Recovery flow invalid. MembershipId: {MembershipId}, FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}, ElapsedMinutes: {Minutes}",
                        cmd.MembershipIdentifier, existingFlow.UniqueId, existingFlow.Purpose, existingFlow.Status,
                        elapsed.TotalMinutes);
                }
                else
                {
                    Log.Warning(
                        "[PASSWORD-RECOVERY-VALIDATION] No verification flow found for membership: {MembershipId}, ExpectedFlowId: {FlowId}",
                        cmd.MembershipIdentifier, membership.VerificationFlowId);
                }

                return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                    new PasswordRecoveryFlowValidation(false, null));
            }

            Log.Information(
                "[PASSWORD-RECOVERY-VALIDATION] Valid recovery flow found. MembershipId: {MembershipId}, FlowId: {FlowId}",
                cmd.MembershipIdentifier, recoveryFlow.UniqueId);

            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Ok(
                new PasswordRecoveryFlowValidation(true, recoveryFlow.UniqueId));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[PASSWORD-RECOVERY-VALIDATION] Exception during validation for MembershipId: {MembershipId}",
                cmd.MembershipIdentifier);
            return Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Validate password recovery flow failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> ExpirePasswordRecoveryFlowsAsync(
        EcliptixSchemaContext ctx, ExpirePasswordRecoveryFlowsEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning("[PASSWORD-RECOVERY-EXPIRE] Membership not found: {MembershipId}",
                    cmd.MembershipIdentifier);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            int rowsAffected = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId &&
                             vf.Purpose == "password_recovery" &&
                             vf.Status == "verified" &&
                             !vf.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(vf => vf.Status, "expired")
                    .SetProperty(vf => vf.UpdatedAt, DateTimeOffset.UtcNow));

            if (rowsAffected > 0)
            {
                Log.Information(
                    "[PASSWORD-RECOVERY-EXPIRE] Expired {Count} recovery flow(s) for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    rowsAffected, cmd.MembershipIdentifier, membership.VerificationFlowId);
            }
            else
            {
                Log.Warning(
                    "[PASSWORD-RECOVERY-EXPIRE] No verified recovery flows to expire for MembershipId: {MembershipId}, FlowId: {FlowId}",
                    cmd.MembershipIdentifier, membership.VerificationFlowId);
            }

            await transaction.CommitAsync(cancellationToken);
            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex, "[PASSWORD-RECOVERY-EXPIRE] Exception while expiring flows for MembershipId: {MembershipId}",
                cmd.MembershipIdentifier);
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Expire password recovery flows failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateMembershipVerificationFlowAsync(
        EcliptixSchemaContext ctx, UpdateMembershipVerificationFlowEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        try
        {
            if (cmd.Purpose != "password_recovery" || cmd.FlowStatus != "verified")
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning(
                    "[UPDATE-MEMBERSHIP-FLOW] Skipping update - Purpose: {Purpose}, Status: {Status}. Only password_recovery + verified are processed",
                    cmd.Purpose, cmd.FlowStatus);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            VerificationFlowEntity? newFlow = await ctx.VerificationFlows
                .Include(vf => vf.MobileNumber)
                .Where(vf => vf.UniqueId == cmd.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (newFlow?.MobileNumber == null)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Verification flow or mobile number not found: {FlowId}",
                    cmd.VerificationFlowId);
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Verification flow or mobile number not found"));
            }

            MembershipEntity? membership = await ctx.Memberships
                .Where(m => m.MobileNumberId == newFlow.MobileNumber.UniqueId && !m.IsDeleted)
                .OrderByDescending(m => m.CreatedAt)
                .FirstOrDefaultAsync();

            if (membership == null)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning("[UPDATE-MEMBERSHIP-FLOW] Membership not found for MobileNumberId: {MobileNumberId}",
                    newFlow.MobileNumber.UniqueId);
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Membership not found"));
            }

            VerificationFlowEntity? currentFlow = await ctx.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync();

            if (currentFlow != null && currentFlow.UpdatedAt >= newFlow.UpdatedAt)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning(
                    "[UPDATE-MEMBERSHIP-FLOW] Skipping update - current flow {CurrentFlowId} (updated: {CurrentUpdated}) is newer than or equal to new flow {NewFlowId} (updated: {NewUpdated})",
                    currentFlow.UniqueId, currentFlow.UpdatedAt, newFlow.UniqueId, newFlow.UpdatedAt);
                return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
            }

            Guid? oldFlowId = membership.VerificationFlowId;

            int rowsAffected = await ctx.Memberships
                .Where(m => m.UniqueId == membership.UniqueId &&
                            m.VerificationFlowId == oldFlowId &&
                            !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.VerificationFlowId, newFlow.UniqueId)
                    .SetProperty(m => m.UpdatedAt, DateTimeOffset.UtcNow));

            if (rowsAffected == 0)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning(
                    "[UPDATE-MEMBERSHIP-FLOW] Optimistic concurrency failure - membership {MembershipId} was modified by another transaction",
                    membership.UniqueId);
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.ConcurrencyConflict("Membership was modified by another transaction"));
            }

            await transaction.CommitAsync(cancellationToken);

            Log.Information(
                "[UPDATE-MEMBERSHIP-FLOW] ✅ Successfully updated membership {MembershipId} VerificationFlowId: {OldFlowId} → {NewFlowId} (Purpose: {Purpose}, CurrentFlowUpdated: {CurrentUpdated}, NewFlowUpdated: {NewUpdated})",
                membership.UniqueId, oldFlowId, newFlow.UniqueId, cmd.Purpose,
                currentFlow?.UpdatedAt.ToString("O") ?? "null", newFlow.UpdatedAt.ToString("O"));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex,
                "[UPDATE-MEMBERSHIP-FLOW] Exception while updating membership verification flow for FlowId: {FlowId}",
                cmd.VerificationFlowId);
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
