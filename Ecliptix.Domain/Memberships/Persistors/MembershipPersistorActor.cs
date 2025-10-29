using System.Collections.Frozen;
using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents.Account;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;
using Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.WorkerActors.Membership;
using Ecliptix.Domain.Schema;
using Ecliptix.Domain.Schema.Entities;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Serilog;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.Domain.Memberships.Persistors;

public class MembershipPersistorActor : PersistorBase<MembershipFailure>
{
    private static readonly FrozenDictionary<string, ProtoMembership.Types.ActivityStatus> MembershipStatusMap =
        new Dictionary<string, ProtoMembership.Types.ActivityStatus>
        {
            ["active"] = ProtoMembership.Types.ActivityStatus.Active,
            ["inactive"] = ProtoMembership.Types.ActivityStatus.Inactive
        }.ToFrozenDictionary();

    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    public MembershipPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
        : base(dbContextFactory)
    {
        _securityConfig = securityConfig;
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() => new MembershipPersistorActor(dbContextFactory, securityConfig));
    }

    private void Ready()
    {
        RegisterHandlers();

        ReceiveAsync<UpdateMembershipVerificationFlowEvent>(async cmd =>
        {
            Log.Information(
                "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Received UpdateMembershipVerificationFlowEvent for FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}",
                cmd.VerificationFlowId, cmd.Purpose, cmd.FlowStatus);

            Result<Unit, MembershipFailure> result = await ExecuteWithContext(
                (ctx, cancellationToken) => UpdateMembershipVerificationFlowAsync(ctx, cmd, cancellationToken),
                "UpdateMembershipVerificationFlow");

            result.Match(
                _ =>
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

        ReceivePersistorCommand<UpdateMembershipCreationStatusEvent, Unit>(
            UpdateMembershipCreationStatusAsync,
            "UpdateMembershipCreationStatus");
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, MembershipFailure>>>
            handler,
        string operationName)
        where TMessage : class, ICancellableActorEvent
    {
        Receive<TMessage>(message =>
        {
            IActorRef replyTo = Sender;
            CancellationToken messageToken = ExtractCancellationToken(message);

            ExecuteWithContext(Operation, operationName, messageToken).PipeTo(replyTo);
            return;

            Task<Result<TResult, MembershipFailure>> Operation(EcliptixSchemaContext schemaContext,
                CancellationToken cancellationToken)
            {
                CancellationToken effectiveToken = CombineCancellationTokens(cancellationToken, messageToken,
                    out CancellationTokenSource? linkedSource);
                try
                {
                    return handler(schemaContext, message, effectiveToken);
                }
                finally
                {
                    linkedSource?.Dispose();
                }
            }
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

    private static Result<MembershipQueryRecord, MembershipFailure> BuildMembershipResult(
        Guid membershipId,
        Guid deviceId,
        Membership.Types.ActivityStatus activityStatus,
        ProtoMembership.Types.CreationStatus creationStatus,
        int credentialsVersion,
        IEnumerable<AccountInfo>? accounts = null,
        Guid? activeAccountId = null,
        byte[]? secureKey = null,
        byte[]? maskingKey = null)
    {
        return Result<MembershipQueryRecord, MembershipFailure>.Ok(
            new MembershipQueryRecord
            {
                UniqueIdentifier = membershipId,
                DeviceId = deviceId,
                ActivityStatus = activityStatus,
                CreationStatus = creationStatus,
                CredentialsVersion = credentialsVersion,
                SecureKey = secureKey ?? [],
                MaskingKey = maskingKey ?? [],
                AvailableAccounts = MaterializeAccounts(accounts),
                ActiveAccountId = activeAccountId
            });
    }

    private static readonly List<AccountInfo> EmptyAccountList = new();

    private static List<AccountInfo> MaterializeAccounts(IEnumerable<AccountInfo>? accounts)
    {
        return accounts switch
        {
            null => EmptyAccountList,
            List<AccountInfo> list => list,
            _ => accounts.ToList()
        };
    }

    private async Task<Result<MembershipQueryRecord, MembershipFailure>> SignInMembershipAsync(
        EcliptixSchemaContext schemaContext,
        SignInMembershipActorEvent cmd,
        CancellationToken cancellationToken)
    {
        MembershipPersistorSettings persistorSettings = _securityConfig.CurrentValue.MembershipPersistor;

        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            Option<LoginAttemptEntity> lockoutMarkerOpt =
                await LoginAttemptQueries.GetMostRecentLockout(schemaContext, cmd.MobileNumber, cancellationToken);
            if (lockoutMarkerOpt.IsSome && lockoutMarkerOpt.Value!.LockedUntil != null)
            {
                LoginAttemptEntity lockoutMarker = lockoutMarkerOpt.Value!;
                if (now < lockoutMarker.LockedUntil!.Value)
                {
                    int remainingMinutes = (int)Math.Ceiling((lockoutMarker.LockedUntil!.Value - now).TotalMinutes);
                    await RollbackSilentlyAsync(transaction);
                    return Result<MembershipQueryRecord, MembershipFailure>.Err(
                        MembershipFailure.ValidationFailed(
                            $"Account is locked. Try again in {remainingMinutes} minutes."));
                }

                await schemaContext.LoginAttempts
                    .Where(la => la.MobileNumber == cmd.MobileNumber &&
                                 la.AttemptedAt <= lockoutMarker.AttemptedAt &&
                                 !la.IsDeleted)
                    .ExecuteDeleteAsync(cancellationToken);
            }

            DateTimeOffset failedLoginLookback = now - persistorSettings.FailedLoginLookback;
            int failedCount =
                await LoginAttemptQueries.CountFailedSince(schemaContext, cmd.MobileNumber, failedLoginLookback,
                    cancellationToken);

            if (failedCount >= persistorSettings.MaxLoginAttemptsInPeriod)
            {
                DateTimeOffset lockedUntil = now + persistorSettings.LoginLockoutDuration;
                int lockoutDurationMinutes = (int)Math.Ceiling(persistorSettings.LoginLockoutDuration.TotalMinutes);
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
                schemaContext.LoginAttempts.Add(lockoutAttempt);
                await schemaContext.SaveChangesAsync(cancellationToken);

                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed(
                        $"Too many login attempts. Try again in {lockoutDurationMinutes} minutes."));
            }

            if (string.IsNullOrEmpty(cmd.MobileNumber))
            {
                LogLoginAttempt(schemaContext, cmd.MobileNumber, "mobile_number_cannot_be_empty", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Mobile number cannot be empty"));
            }

            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByMobileNumber(schemaContext, cmd.MobileNumber, cancellationToken);
            if (!membershipOpt.IsSome)
            {
                LogLoginAttempt(schemaContext, cmd.MobileNumber, "mobile_number_not_found", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.NotFoundByMobile("Mobile number not found"));
            }

            MembershipEntity membership = membershipOpt.Value!;

            Option<AccountEntity> defaultAccountOpt =
                await AccountQueries.GetDefaultAccountByMembershipId(schemaContext, membership.UniqueId);

            if (!defaultAccountOpt.IsSome)
            {
                LogLoginAttempt(schemaContext, cmd.MobileNumber, "default_account_not_found", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Default account not found for this membership"));
            }

            Option<AccountSecureKeyAuthEntity> defaultAuthOpt =
                await AccountSecureKeyAuthQueries.GetPrimaryForAccount(schemaContext, defaultAccountOpt.Value.UniqueId);

            if (!defaultAuthOpt.IsSome)
            {
                LogLoginAttempt(schemaContext, cmd.MobileNumber, "secure_key_not_set", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Secure key not set for this account"));
            }

            if (membership.Status != MembershipStatus.Active)
            {
                LogLoginAttempt(schemaContext, cmd.MobileNumber, "inactive_membership", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.InvalidStatus("Membership is inactive"));
            }

            LogLoginAttempt(schemaContext, cmd.MobileNumber, "success", true, now, membershipId: membership.UniqueId);

            await schemaContext.LoginAttempts
                .Where(la => la.MobileNumber == cmd.MobileNumber &&
                             (!la.IsSuccess || la.LockedUntil != null) &&
                             !la.IsDeleted)
                .ExecuteDeleteAsync(cancellationToken);

            List<AccountInfo> accounts =
                await AccountQueries.GetAccountsByMembershipId(schemaContext, membership.UniqueId, cancellationToken);

            DeviceContextEntity? deviceContext = await schemaContext.DeviceContexts
                .Where(dc => dc.MembershipId == membership.UniqueId &&
                             dc.DeviceId == cmd.DeviceId &&
                             dc.IsActive &&
                             !dc.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            bool createdDeviceContext = false;
            DeviceContextEntity? pendingDeviceContext = null;

            if (deviceContext == null)
            {
                bool deviceExists = await schemaContext.Devices
                    .Where(d => d.DeviceId == cmd.DeviceId && !d.IsDeleted)
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
                            ContextExpiresAt = now + persistorSettings.DeviceContextExpiration,
                            LastActivityAt = now,
                            IsActive = true
                        };
                        schemaContext.DeviceContexts.Add(pendingDeviceContext);
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
                await schemaContext.SaveChangesAsync(cancellationToken);

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

                schemaContext.Entry(pendingDeviceContext).State = EntityState.Detached;
                deviceContext = null;
                await schemaContext.SaveChangesAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            Option<AccountSecureKeyAuthEntity> authOpt;
            await using (EcliptixSchemaContext freshContext = await DbContextFactory.CreateDbContextAsync(cancellationToken))
            {
                authOpt = await AccountSecureKeyAuthQueries.GetPrimaryForActiveAccount(
                    freshContext,
                    membership.UniqueId,
                    cmd.DeviceId);
            }

            if (!authOpt.IsSome)
            {
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Credentials not found for this account"));
            }

            AccountSecureKeyAuthEntity auth = authOpt.Value;
            CredentialsRecord credentials = new(auth.SecureKey, auth.MaskingKey, auth.CredentialsVersion);
            return BuildMembershipResult(
                membership.UniqueId,
                membership.AppDeviceId,
                membership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                ProtoMembership.Types.CreationStatus.OtpVerified,
                credentials.Version,
                accounts,
                deviceContext?.ActiveAccountId,
                credentials.SecureKey,
                credentials.MaskingKey);
        }
        catch (OperationCanceledException)
        {
            await RollbackSilentlyAsync(transaction);
            throw;
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<MembershipQueryRecord, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Login operation failed", ex));
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

    private async Task<Result<MembershipQueryRecord, MembershipFailure>> CreateMembershipAsync(
        EcliptixSchemaContext ctx, CreateMembershipActorEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, cancellationToken);
        try
        {
            MembershipPersistorSettings persistorSettings = _securityConfig.CurrentValue.MembershipPersistor;

            Option<VerificationFlowEntity> flowOpt = await VerificationFlowQueries.GetByUniqueIdAndConnectionId(
                ctx, cmd.VerificationFlowIdentifier, cmd.ConnectId, cancellationToken);

            if (!flowOpt.IsSome)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Verification flow not found for membership creation"));
            }

            VerificationFlowEntity flow = flowOpt.Value!;

            Guid mobileUniqueId = flow.MobileNumber.UniqueId;
            string mobileNumber = flow.MobileNumber.Number;

            DateTimeOffset creationWindowStart = DateTimeOffset.UtcNow - persistorSettings.MembershipCreationWindow;
            int failedAttempts =
                await LoginAttemptQueries.CountFailedMembershipCreationSince(ctx, mobileUniqueId, creationWindowStart,
                    cancellationToken);

            if (failedAttempts >= persistorSettings.MaxMembershipCreationAttempts)
            {
                Option<DateTimeOffset> earliestFailedOpt =
                    await LoginAttemptQueries.GetEarliestFailedMembershipCreationSince(ctx, mobileUniqueId,
                        creationWindowStart,
                        cancellationToken);
                if (earliestFailedOpt.IsSome)
                {
                    DateTimeOffset waitUntil = earliestFailedOpt.Value + persistorSettings.MembershipCreationWindow;
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
                    return Result<MembershipQueryRecord, MembershipFailure>.Err(
                        MembershipFailure.ValidationFailed(
                            $"Too many membership creation attempts. Try again in {waitMinutes} minutes."));
                }
            }

            Option<MembershipEntity> existingMembershipOpt = await MembershipQueries.GetByMobileUniqueIdAndDevice(
                ctx, mobileUniqueId, flow.AppDeviceId, cancellationToken);

            if (existingMembershipOpt.IsSome)
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

                ProtoMembership.Types.CreationStatus existingCreationStatus = existingMembership.CreationStatus switch
                {
                    MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                    MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                    MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                    null => ProtoMembership.Types.CreationStatus.OtpVerified,
                    _ => ProtoMembership.Types.CreationStatus.OtpVerified
                };

                Option<CredentialsRecord> existingCredentialsOpt =
                    await AccountSecureKeyAuthQueries.GetCredentialsForMembership(ctx, existingMembership.UniqueId);

                return BuildMembershipResult(
                    existingMembership.UniqueId,
                    existingMembership.AppDeviceId,
                    existingMembership.Status switch
                    {
                        MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                        MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                        _ => Membership.Types.ActivityStatus.Active
                    },
                    existingCreationStatus,
                    existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value.Version : 0,
                    secureKey: existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value.SecureKey : null,
                    maskingKey: existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value.MaskingKey : null);
            }

            MembershipEntity newMembership = new()
            {
                MobileNumberId = mobileUniqueId,
                AppDeviceId = flow.AppDeviceId,
                VerificationFlowId = flow.UniqueId,
                Status = MembershipStatus.Active,
                CreationStatus = cmd.CreationStatus switch
                {
                    ProtoMembership.Types.CreationStatus.OtpVerified => MembershipCreationStatus.OtpVerified,
                    ProtoMembership.Types.CreationStatus.SecureKeySet => MembershipCreationStatus.SecureKeySet,
                    ProtoMembership.Types.CreationStatus.PassphraseSet => MembershipCreationStatus.PassphraseSet,
                    _ => MembershipCreationStatus.OtpVerified
                }
            };
            ctx.Memberships.Add(newMembership);
            await ctx.SaveChangesAsync(cancellationToken);

            await ctx.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentifier && o.VerificationFlowId == flow.Id && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, OtpStatus.Used)
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
                    (la, m) => new LoginAttemptMembershipQueryRecord { LoginAttempt = la, Membership = m })
                .Where(x => x.Membership.MobileNumberId == mobileUniqueId &&
                            x.LoginAttempt.Outcome == "membership_creation" &&
                            !x.LoginAttempt.IsSuccess &&
                            !x.LoginAttempt.IsDeleted &&
                            !x.Membership.IsDeleted)
                .Select(x => x.LoginAttempt.Id)
                .ToListAsync(cancellationToken);

            if (failedAttemptIds.Count > 0)
            {
                await ctx.LoginAttempts
                    .Where(la => failedAttemptIds.Contains(la.Id))
                    .ExecuteDeleteAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            ProtoMembership.Types.CreationStatus newMembershipCreationStatus = newMembership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                null => ProtoMembership.Types.CreationStatus.OtpVerified,
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            return BuildMembershipResult(
                newMembership.UniqueId,
                newMembership.AppDeviceId,
                newMembership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                newMembershipCreationStatus,
                credentialsVersion: 0);
        }
        catch (OperationCanceledException ex)
        {
            Log.Error(ex, "[CREATE-MEMBERSHIP] Operation cancelled. FlowId={FlowId} ConnectId={ConnectId}",
                cmd.VerificationFlowIdentifier, cmd.ConnectId);

            await RollbackSilentlyAsync(transaction);
            throw;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[CREATE-MEMBERSHIP] Transaction failed. FlowId={FlowId} ConnectId={ConnectId}",
                cmd.VerificationFlowIdentifier, cmd.ConnectId);

            await RollbackSilentlyAsync(transaction);
            return Result<MembershipQueryRecord, MembershipFailure>.Err(
                MembershipFailure.CreationFailed(ex));
        }
    }

    private async Task<Result<MembershipQueryRecord, MembershipFailure>> GetMembershipByVerificationFlowAsync(
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
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Verification flow not found"));
            }

            MembershipEntity? membership;

            if (verificationFlow.Purpose == VerificationPurpose.PasswordRecovery)
            {
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
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.NotFound());
            }

            Log.Information("[GET-MEMBERSHIP-BY-FLOW] Membership found: {MembershipId} for flow: {FlowId}",
                membership.UniqueId, cmd.VerificationFlowId);

            ProtoMembership.Types.CreationStatus creationStatus = membership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                null => ProtoMembership.Types.CreationStatus.OtpVerified,
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForMembership(ctx, membership.UniqueId);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.AppDeviceId,
                membership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                creationStatus,
                credentialsOpt.IsSome ? credentialsOpt.Value.Version : 0,
                secureKey: credentialsOpt.IsSome ? credentialsOpt.Value.SecureKey : null,
                maskingKey: credentialsOpt.IsSome ? credentialsOpt.Value.MaskingKey : null);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[GET-MEMBERSHIP-BY-FLOW] Exception while getting membership for flow: {FlowId}",
                cmd.VerificationFlowId);
            return Result<MembershipQueryRecord, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to get membership by verification flow", ex));
        }
    }

    private async Task<Result<MembershipQueryRecord, MembershipFailure>> GetMembershipByUniqueIdAsync(
        EcliptixSchemaContext ctx,
        GetMembershipByUniqueIdEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByUniqueId(ctx, cmd.MembershipUniqueId, cancellationToken);

            if (!membershipOpt.IsSome)
            {
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.NotFoundById());
            }

            MembershipEntity membership = membershipOpt.Value!;

            ProtoMembership.Types.CreationStatus creationStatus = membership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                null => ProtoMembership.Types.CreationStatus.OtpVerified,
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForMembership(ctx, membership.UniqueId);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.AppDeviceId,
                membership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                creationStatus,
                credentialsOpt.IsSome ? credentialsOpt.Value.Version : 0,
                secureKey: credentialsOpt.IsSome ? credentialsOpt.Value.SecureKey : null,
                maskingKey: credentialsOpt.IsSome ? credentialsOpt.Value.MaskingKey : null);
        }
        catch (Exception ex)
        {
            return Result<MembershipQueryRecord, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to get membership by unique ID", ex));
        }
    }

    private static async Task<Result<Unit, MembershipFailure>> UpdateMembershipCreationStatusAsync(
        EcliptixSchemaContext ctx,
        UpdateMembershipCreationStatusEvent cmd,
        CancellationToken cancellationToken)
    {
        try
        {
            int rowsAffected = await ctx.Memberships
                .Where(m => m.UniqueId == cmd.MembershipIdentifier && !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.CreationStatus, cmd.CreationStatus)
                    .SetProperty(m => m.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

            if (rowsAffected == 0)
            {
                Log.Warning(
                    "[UPDATE-CREATION-STATUS] Membership not found. MembershipId={0}",
                    cmd.MembershipIdentifier);
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.NotFoundById());
            }

            Log.Information(
                "[UPDATE-CREATION-STATUS] Successfully updated membership {0} to {1}",
                cmd.MembershipIdentifier, cmd.CreationStatus);

            return Result<Unit, MembershipFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "[UPDATE-CREATION-STATUS] Failed to update membership creation status. MembershipId={0}",
                cmd.MembershipIdentifier);
            return Result<Unit, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to update membership creation status", ex));
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

    private async Task<Result<Unit, MembershipFailure>> UpdateMembershipVerificationFlowAsync(
        EcliptixSchemaContext ctx, UpdateMembershipVerificationFlowEvent cmd, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await ctx.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        try
        {
            if (cmd.Purpose != VerificationPurpose.PasswordRecovery ||
                cmd.FlowStatus != VerificationFlowStatus.Verified)
            {
                await RollbackSilentlyAsync(transaction);
                Log.Warning(
                    "[UPDATE-MEMBERSHIP-FLOW] Skipping update - Purpose: {Purpose}, Status: {Status}. Only password_recovery + verified are processed",
                    cmd.Purpose, cmd.FlowStatus);
                return Result<Unit, MembershipFailure>.Ok(Unit.Value);
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
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Verification flow not found or invalid"));
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
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.NotFound());
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
                return Result<Unit, MembershipFailure>.Ok(Unit.Value);
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
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.UpdateFailed(new Exception("Optimistic concurrency failure")));
            }

            await transaction.CommitAsync(cancellationToken);

            Log.Information(
                "[UPDATE-MEMBERSHIP-FLOW] ✅ Successfully updated membership {MembershipId} VerificationFlowId: {OldFlowId} → {NewFlowId} (Purpose: {Purpose}, CurrentFlowUpdated: {CurrentUpdated}, NewFlowUpdated: {NewUpdated})",
                membership.UniqueId, oldFlowId, newFlow.UniqueId, cmd.Purpose,
                currentFlow?.UpdatedAt.ToString("O") ?? "null", newFlow.UpdatedAt.ToString("O"));

            return Result<Unit, MembershipFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            Log.Error(ex,
                "[UPDATE-MEMBERSHIP-FLOW] Exception while updating membership verification flow for FlowId: {FlowId}",
                cmd.VerificationFlowId);
            return Result<Unit, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to update membership verification flow", ex));
        }
    }

    protected override MembershipFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => MembershipFailure.AlreadyExists($"Unique constraint violation: {sqlEx.Message}"),
                547 => MembershipFailure.ValidationFailed($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => MembershipFailure.DatabaseError(sqlEx),
                -2 => MembershipFailure.Timeout(sqlEx),
                2 => MembershipFailure.DatabaseError(sqlEx),
                18456 => MembershipFailure.DatabaseError(sqlEx),
                _ => MembershipFailure.DatabaseError(sqlEx)
            };
        }

        return MembershipFailure.DatabaseError(ex);
    }

    protected override MembershipFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return MembershipFailure.Timeout(ex);
    }

    protected override MembershipFailure CreateGenericFailure(Exception ex)
    {
        return MembershipFailure.InternalError($"Unexpected error in membership persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}
