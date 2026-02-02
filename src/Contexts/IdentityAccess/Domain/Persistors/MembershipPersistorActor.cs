using System.Data.Common;
using Akka.Actor;
using Ecliptix.IdentityAccess.Domain.Memberships;
using Ecliptix.IdentityAccess.Domain.Actors.Membership;
using Ecliptix.IdentityAccess.Domain.Memberships.Otp;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.CompiledQueries;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.Protobuf.Account;
using Ecliptix.Protobuf.Membership;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;
using Serilog;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;
using OtpVerificationPurpose = Ecliptix.IdentityAccess.Domain.Memberships.OtpVerificationPurpose;

namespace Ecliptix.IdentityAccess.Domain.Persistors;

public class MembershipPersistorActor : PersistorBase<MembershipFailure>
{
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private const string DefaultOutcome = "membership_creation";

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

        ReceiveAsync<UpdateMembershipVerificationFlowCommand>(async command =>
        {
            Log.Information(
                "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Received UpdateMembershipVerificationFlowCommand for FlowId: {FlowId}, Purpose: {Purpose}, Status: {Status}",
                command.VerificationFlowId, command.Purpose, command.FlowStatus);

            Result<Unit, MembershipFailure> result = await ExecuteWithContext(
                (schemaContext, cancellationToken) => UpdateMembershipVerificationFlowAsync(schemaContext, command, cancellationToken),
                PersistorOperation.UpdateMembershipVerificationFlow);

            result.Match(
                _ =>
                {
                    Log.Information(
                        "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Successfully processed event for FlowId: {FlowId}",
                        command.VerificationFlowId);
                    return Unit.Value;
                },
                err =>
                {
                    Log.Error(
                        "[UPDATE-MEMBERSHIP-FLOW-RECEIVED] Failed to process event for FlowId: {FlowId}, Error: {Error}",
                        command.VerificationFlowId, err.Message);
                    return Unit.Value;
                }
            );

            Sender.Tell(result);
        });
    }

    private void RegisterHandlers()
    {
        ReceivePersistorCommand<CreateMembershipCommand, MembershipQueryRecord>(
            CreateMembershipAsync,
            PersistorOperation.CreateMembership);

        ReceivePersistorCommand<SignInMembershipCommand, MembershipQueryRecord>(
            SignInMembershipAsync,
            PersistorOperation.LoginMembership);

        ReceivePersistorCommand<GetMembershipByVerificationFlowQuery, MembershipQueryRecord>(
            GetMembershipByVerificationFlowAsync,
            PersistorOperation.GetMembershipByVerificationFlow);

        ReceivePersistorCommand<GetMembershipByUniqueIdQuery, MembershipQueryRecord>(
            GetMembershipByUniqueIdAsync,
            PersistorOperation.GetMembershipByUniqueId);

        ReceivePersistorCommand<UpdateMembershipCreationStatusCommand, Unit>(
            UpdateMembershipCreationStatusAsync,
            PersistorOperation.UpdateMembershipCreationStatus);

        ReceivePersistorCommand<GetMembershipStateQuery, MembershipStateQueryRecord>(
            GetMembershipStateAsync,
            PersistorOperation.GetMembershipState);
    }

    private void ReceivePersistorCommand<TMessage, TResult>(
        Func<EcliptixSchemaContext, TMessage, CancellationToken, Task<Result<TResult, MembershipFailure>>>
            handler,
        PersistorOperation operationName)
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
                    out CancellationTokenSource? linkedCancellationTokenSource);
                try
                {
                    return handler(schemaContext, message, effectiveToken);
                }
                finally
                {
                    linkedCancellationTokenSource?.Dispose();
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
        out CancellationTokenSource? linkedCancellationTokenSource)
    {
        linkedCancellationTokenSource = null;

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

        linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(first, second);
        return linkedCancellationTokenSource.Token;
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
        int opaqueKeyVersion,
        IEnumerable<AccountInfo>? accounts = null,
        Guid? activeAccountId = null,
        Guid? credentialsAccountId = null,
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
                OpaqueKeyVersion = opaqueKeyVersion,
                SecureKey = secureKey ?? [],
                MaskingKey = maskingKey ?? [],
                CredentialsAccountId = credentialsAccountId,
                AvailableAccounts = MaterializeAccounts(accounts),
                ActiveAccountId = activeAccountId
            });
    }

    private static readonly List<AccountInfo> EmptyAccountList = [];

    private static List<AccountInfo> MaterializeAccounts(IEnumerable<AccountInfo>? accounts)
    {
        return accounts switch
        {
            null => EmptyAccountList,
            List<AccountInfo> list => list,
            _ => accounts.ToList()
        };
    }

   private static async Task<Result<MembershipStateQueryRecord, MembershipFailure>> GetMembershipStateAsync(
        EcliptixSchemaContext schemaContext,
        GetMembershipStateQuery query,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MembershipStateResult> stateOpt =
                await MembershipQueries.GetStateByUniqueId(schemaContext, query.MembershipId, cancellationToken);

            if (!stateOpt.IsSome)
            {
                return Result<MembershipStateQueryRecord, MembershipFailure>.Ok(new MembershipStateQueryRecord
                {
                    AvailabilityStatus = MobileNumberAvailabilityStatus.MobileNumberAvailabilityAvailable,
                    ActivityStatus = Membership.Types.ActivityStatus.Inactive,
                    CreationStatus = Membership.Types.CreationStatus.OtpVerified,
                    CanContinue = false,
                    LocalizationKey = "Membership.State.NotFound"
                });
            }

            MembershipStateResult membership = stateOpt.Value!;

            Membership.Types.CreationStatus creationStatus = membership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => Membership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => Membership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => Membership.Types.CreationStatus.PassphraseSet,
                MembershipCreationStatus.ProfileSet => Membership.Types.CreationStatus.ProfileSet,
                _ => Membership.Types.CreationStatus.OtpVerified
            };

            Membership.Types.ActivityStatus activityStatus = membership.Status switch
            {
                MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                _ => Membership.Types.ActivityStatus.Active
            };

            bool isRegistrationComplete = creationStatus == Membership.Types.CreationStatus.PassphraseSet;
            bool isSameDevice = membership.DeviceId == query.RequestingDeviceId;
            bool isActive = activityStatus == Membership.Types.ActivityStatus.Active;

            MobileNumberAvailabilityStatus availabilityStatus;
            bool canContinue;
            string locKey;

            if (!isActive)
            {
                availabilityStatus = MobileNumberAvailabilityStatus.MobileNumberAvailabilityTakenInactive;
                canContinue = false;
                locKey = "Membership.State.Inactive";
            }
            else if (isRegistrationComplete)
            {
                availabilityStatus = MobileNumberAvailabilityStatus.MobileNumberAvailabilityTakenActive;
                canContinue = true;
                locKey = "Membership.State.ReadyForLogin";
            }
            else
            {
                if (isSameDevice)
                {
                    availabilityStatus = MobileNumberAvailabilityStatus.MobileNumberAvailabilityIncompleteRegistration;
                    canContinue = true;
                    locKey = "Membership.State.ResumeRegistration";
                }
                else
                {
                    availabilityStatus = MobileNumberAvailabilityStatus.MobileNumberAvailabilityIncompleteRegistration;
                    canContinue = false;
                    locKey = "Membership.State.DifferentDevice";
                }
            }

            return Result<MembershipStateQueryRecord, MembershipFailure>.Ok(new MembershipStateQueryRecord
            {
                AvailabilityStatus = availabilityStatus,
                CreationStatus = creationStatus,
                ActivityStatus = activityStatus,
                CanContinue = canContinue,
                LocalizationKey = locKey
            });
        }
        catch (Exception ex)
        {
            return Result<MembershipStateQueryRecord, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to get membership state", ex));
        }
    }

    private async Task<Result<MembershipQueryRecord, MembershipFailure>> SignInMembershipAsync(
        EcliptixSchemaContext schemaContext,
        SignInMembershipCommand command,
        CancellationToken cancellationToken)
    {
        MembershipPersistorSettings persistorSettings = _securityConfig.CurrentValue.MembershipPersistor;

        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            Option<LoginAttemptEntity> lockoutMarkerOpt =
                await LoginAttemptQueries.GetMostRecentLockout(schemaContext, command.MobileNumber, cancellationToken);
            if (lockoutMarkerOpt.IsSome && lockoutMarkerOpt.Value!.LockedUntil != null)
            {
                LoginAttemptEntity lockoutMarker = lockoutMarkerOpt.Value!;
                if (now < lockoutMarker.LockedUntil!.Value)
                {
                    int remainingMinutes = (int)Math.Ceiling((lockoutMarker.LockedUntil!.Value - now).TotalMinutes);
                    await RollbackSilentlyAsync(transaction);
                    return Result<MembershipQueryRecord, MembershipFailure>.Err(
                        MembershipFailure.RateLimitExceeded(
                            $"Account is locked. Try again in {remainingMinutes} minutes."));
                }

                await schemaContext.LoginAttempts
                    .Where(la => la.MobileNumber == command.MobileNumber &&
                                 la.AttemptedAt <= lockoutMarker.AttemptedAt &&
                                 !la.IsDeleted)
                    .ExecuteDeleteAsync(cancellationToken);
            }

            MembershipPersistorSettings settings = _securityConfig.CurrentValue.MembershipPersistor;

            DateTimeOffset velocityLookback =
                now.AddMinutes(-settings.InitAttemptsInWindowMinutes);

            int maxInitAttempts = settings.MaxSignInInitAttempts;

            int recentActivityCount = await schemaContext.LoginAttempts
                .CountAsync(la => la.MobileNumber == command.MobileNumber &&
                                  la.AttemptedAt > velocityLookback &&
                                  !la.IsDeleted,
                    cancellationToken);

            if (recentActivityCount >= maxInitAttempts)
            {
                schemaContext.LoginAttempts.Add(new LoginAttemptEntity
                {
                    MobileNumber = command.MobileNumber,
                    Outcome = "velocity_limit_exceeded",
                    IsSuccess = false,
                    AttemptedAt = now
                });

                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);

                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.RateLimitExceeded(
                        $"Too many initialization requests. Please wait {settings.InitAttemptsInWindowMinutes} minutes."));
            }

            DateTimeOffset failedLoginLookback = now - persistorSettings.FailedLoginLookback;
            int failedCount =
                await LoginAttemptQueries.CountFailedSince(schemaContext, command.MobileNumber, failedLoginLookback,
                    cancellationToken);

            if (failedCount >= persistorSettings.MaxLoginAttemptsInPeriod)
            {
                DateTimeOffset lockedUntil = now + persistorSettings.LoginLockoutDuration;
                int lockoutDurationMinutes = (int)Math.Ceiling(persistorSettings.LoginLockoutDuration.TotalMinutes);
                LoginAttemptEntity lockoutAttempt = new()
                {
                    MobileNumber = command.MobileNumber,
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
                    MembershipFailure.RateLimitExceeded(
                        $"Too many login attempts. Try again in {lockoutDurationMinutes} minutes."));
            }

            if (string.IsNullOrEmpty(command.MobileNumber))
            {
                LogLoginAttempt(schemaContext, command.MobileNumber, "mobile_number_cannot_be_empty", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Mobile number cannot be empty"));
            }

            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByMobileNumber(schemaContext, command.MobileNumber, cancellationToken);
            if (!membershipOpt.IsSome)
            {
                LogLoginAttempt(schemaContext, command.MobileNumber, "mobile_number_not_found", false, now);
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
                LogLoginAttempt(schemaContext, command.MobileNumber, "default_account_not_found", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Default account not found for this membership"));
            }

            Option<AccountSecureKeyAuthEntity> defaultAuthOpt =
                await AccountSecureKeyAuthQueries.GetPrimaryForAccount(schemaContext, defaultAccountOpt.Value!.UniqueId);

            if (!defaultAuthOpt.IsSome)
            {
                LogLoginAttempt(schemaContext, command.MobileNumber, "secure_key_not_set", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Secure key not set for this account"));
            }

            if (membership.Status != MembershipStatus.Active)
            {
                LogLoginAttempt(schemaContext, command.MobileNumber, "inactive_membership", false, now);
                await schemaContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.InvalidStatus("Membership is inactive"));
            }

            LogLoginAttempt(schemaContext, command.MobileNumber, "success", true, now, membershipId: membership.UniqueId);

            await schemaContext.LoginAttempts
                .Where(la => la.MobileNumber == command.MobileNumber &&
                             (!la.IsSuccess || la.LockedUntil != null) &&
                             !la.IsDeleted)
                .ExecuteDeleteAsync(cancellationToken);

            List<AccountInfo> accounts =
                await AccountQueries.GetAccountsByMembershipId(schemaContext, membership.UniqueId, cancellationToken);

            DeviceContextEntity? deviceContext = await schemaContext.DeviceContexts
                .Where(dc => dc.MembershipId == membership.UniqueId &&
                             dc.DeviceId == command.DeviceId &&
                             dc.IsActive &&
                             !dc.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            bool createdDeviceContext = false;
            DeviceContextEntity? pendingDeviceContext = null;

            if (deviceContext == null)
            {
                bool deviceExists = await schemaContext.Devices
                    .Where(d => d.DeviceId == command.DeviceId && !d.IsDeleted)
                    .AnyAsync(cancellationToken);

                if (deviceExists)
                {
                    AccountInfo? defaultAccount = accounts.FirstOrDefault(a => a.IsDefault);
                    if (defaultAccount != null)
                    {
                        pendingDeviceContext = new DeviceContextEntity
                        {
                            MembershipId = membership.UniqueId,
                            DeviceId = command.DeviceId,
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
                        command.DeviceId, membership.UniqueId);
                }
            }

            try
            {
                await schemaContext.SaveChangesAsync(cancellationToken);

                if (createdDeviceContext && deviceContext != null)
                {
                    Log.Information(
                        "[SIGN-IN] Created device context for Device: {DeviceId}, Membership: {MembershipId}",
                        command.DeviceId, membership.UniqueId);
                }
            }
            catch (DbUpdateException dbEx) when (createdDeviceContext &&
                                                 pendingDeviceContext != null &&
                                                 dbEx.InnerException is PostgresException
                                                     { SqlState: PostgresErrorCodes.ForeignKeyViolation })
            {
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
                    command.DeviceId);
            }

            if (!authOpt.IsSome)
            {
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Credentials not found for this account"));
            }

            AccountSecureKeyAuthEntity auth = authOpt.Value!;
            CredentialsRecord credentials = new(auth.SecureKey, auth.MaskingKey, auth.CredentialsVersion, auth.OpaqueKeyVersion);
            return BuildMembershipResult(
                membership.UniqueId,
                membership.DeviceId,
                membership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                ProtoMembership.Types.CreationStatus.OtpVerified,
                credentials.Version,
                credentials.OpaqueKeyVersion,
                accounts,
                deviceContext?.ActiveAccountId,
                auth.AccountId,
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

    private static void LogLoginAttempt(EcliptixSchemaContext schemaContext, string mobileNumber, string outcome, bool isSuccess,
        DateTimeOffset timestamp, Guid? membershipId = null, string? ipAddress = null, string? platform = null)
    {
        LoginAttemptEntity attempt = new()
        {
            MembershipId = membershipId,
            MobileNumber = mobileNumber,
            Outcome = outcome,
            IsSuccess = isSuccess,
            AttemptedAt = timestamp,
            CompletedAt = isSuccess ? timestamp : null,
            IpAddress = ipAddress,
            Platform = platform
        };
        schemaContext.LoginAttempts.Add(attempt);
    }

    private async Task<Result<MembershipQueryRecord, MembershipFailure>> CreateMembershipAsync(
        EcliptixSchemaContext schemaContext, CreateMembershipCommand command, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, cancellationToken);
        try
        {
            MembershipPersistorSettings persistorSettings = _securityConfig.CurrentValue.MembershipPersistor;

            Option<VerificationFlowEntity> flowOpt = await VerificationFlowQueries.GetByUniqueIdAndConnectionId(
                schemaContext, command.VerificationFlowIdentifier, command.ConnectId, cancellationToken);

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
                await LoginAttemptQueries.CountFailedMembershipCreationSince(schemaContext, mobileUniqueId, creationWindowStart,
                    cancellationToken);

            if (failedAttempts >= persistorSettings.MaxMembershipCreationAttempts)
            {
                Option<DateTimeOffset> earliestFailedOpt =
                    await LoginAttemptQueries.GetEarliestFailedMembershipCreationSince(schemaContext, mobileUniqueId,
                        creationWindowStart,
                        cancellationToken);
                if (earliestFailedOpt.IsSome)
                {
                    DateTimeOffset waitUntil = earliestFailedOpt.Value + persistorSettings.MembershipCreationWindow;
                    int waitMinutes = (int)Math.Max(0, (waitUntil - DateTimeOffset.UtcNow).TotalMinutes);

                    LoginAttemptEntity rateLimitAttempt = new()
                    {
                        MembershipId = mobileUniqueId,
                        MobileNumber = mobileNumber,
                        Outcome = DefaultOutcome,
                        IsSuccess = false,
                        ErrorMessage = "rate_limit_exceeded",
                        AttemptedAt = DateTimeOffset.UtcNow,
                        IpAddress = null,
                        Platform = null
                    };
                    schemaContext.LoginAttempts.Add(rateLimitAttempt);
                    await schemaContext.SaveChangesAsync(cancellationToken);

                    await RollbackSilentlyAsync(transaction);
                    return Result<MembershipQueryRecord, MembershipFailure>.Err(
                        MembershipFailure.ValidationFailed(
                            $"Too many membership creation attempts. Try again in {waitMinutes} minutes."));
                }
            }

            Option<MembershipEntity> existingMembershipOpt = await MembershipQueries.GetByMobileUniqueIdAndDevice(
                schemaContext, mobileUniqueId, flow.DeviceId, cancellationToken);

            if (existingMembershipOpt.IsSome)
            {
                MembershipEntity existingMembership = existingMembershipOpt.Value!;
                LoginAttemptEntity attempt = new()
                {
                    MembershipId = existingMembership.UniqueId,
                    MobileNumber = mobileNumber,
                    Outcome = DefaultOutcome,
                    IsSuccess = false,
                    ErrorMessage = "membership_already_exists",
                    AttemptedAt = DateTimeOffset.UtcNow,
                    IpAddress = null,
                    Platform = null
                };
                schemaContext.LoginAttempts.Add(attempt);
                await schemaContext.SaveChangesAsync(cancellationToken);

                await RollbackSilentlyAsync(transaction);

                ProtoMembership.Types.CreationStatus existingCreationStatus = existingMembership.CreationStatus switch
                {
                    MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                    MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                    MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                    _ => ProtoMembership.Types.CreationStatus.OtpVerified
                };

                Option<CredentialsRecord> existingCredentialsOpt =
                    await AccountSecureKeyAuthQueries.GetCredentialsForMembership(schemaContext, existingMembership.UniqueId);

                return BuildMembershipResult(
                    existingMembership.UniqueId,
                    existingMembership.DeviceId,
                    existingMembership.Status switch
                    {
                        MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                        MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                        _ => Membership.Types.ActivityStatus.Active
                    },
                    existingCreationStatus,
                    existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value!.Version : 0,
                    existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value!.OpaqueKeyVersion : 0,
                    secureKey: existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value!.SecureKey : null,
                    maskingKey: existingCredentialsOpt.IsSome ? existingCredentialsOpt.Value!.MaskingKey : null);
            }

            MembershipEntity newMembership = new()
            {
                MobileNumberId = mobileUniqueId,
                DeviceId = flow.DeviceId,
                VerificationFlowId = flow.UniqueId,
                Status = MembershipStatus.Active,
                CreationStatus = command.CreationStatus switch
                {
                    ProtoMembership.Types.CreationStatus.OtpVerified => MembershipCreationStatus.OtpVerified,
                    ProtoMembership.Types.CreationStatus.SecureKeySet => MembershipCreationStatus.SecureKeySet,
                    ProtoMembership.Types.CreationStatus.PassphraseSet => MembershipCreationStatus.PassphraseSet,
                    _ => MembershipCreationStatus.OtpVerified
                }
            };
            schemaContext.Memberships.Add(newMembership);
            await schemaContext.SaveChangesAsync(cancellationToken);

            AccountEntity defaultAccount = new()
            {
                MembershipId = newMembership.UniqueId,
                AccountType = AccountType.Personal,
                Status = AccountStatus.Active,
                IsDefaultAccount = true
            };
            schemaContext.Accounts.Add(defaultAccount);

            bool deviceExists = await schemaContext.Devices
                .Where(d => d.DeviceId == flow.DeviceId && !d.IsDeleted)
                .AnyAsync(cancellationToken);

            DeviceContextEntity? pendingDeviceContext = null;
            if (deviceExists)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                pendingDeviceContext = new DeviceContextEntity
                {
                    MembershipId = newMembership.UniqueId,
                    DeviceId = flow.DeviceId,
                    ActiveAccountId = null,
                    ContextEstablishedAt = now,
                    ContextExpiresAt = now + persistorSettings.DeviceContextExpiration,
                    LastActivityAt = now,
                    IsActive = true
                };
                schemaContext.DeviceContexts.Add(pendingDeviceContext);
            }
            else
            {
                Log.Warning(
                    "[CREATE-MEMBERSHIP] Device {DeviceId} not found, skipping device context creation. Membership: {MembershipId}",
                    flow.DeviceId,
                    newMembership.UniqueId);
            }

            VerificationLogEntity verificationLog = new()
            {
                MembershipId = newMembership.UniqueId,
                MobileNumberId = flow.MobileNumberId,
                DeviceId = flow.DeviceId,
                AccountId = null,
                Purpose = flow.Purpose,
                Status = VerificationFlowStatus.Verified,
                OtpCount = flow.OtpCount,
                VerifiedAt = DateTimeOffset.UtcNow,
                ExpiresAt = flow.ExpiresAt
            };
            schemaContext.VerificationLogs.Add(verificationLog);

            await schemaContext.OtpCodes
                .Where(o => o.UniqueId == command.OtpIdentifier && o.VerificationFlowId == flow.Id && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, OtpStatus.Used)
                    .SetProperty(o => o.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

            LoginAttemptEntity successAttempt = new()
            {
                MembershipId = newMembership.UniqueId,
                MobileNumber = mobileNumber,
                Outcome = DefaultOutcome,
                IsSuccess = true,
                ErrorMessage = "created",
                AttemptedAt = DateTimeOffset.UtcNow,
                CompletedAt = DateTimeOffset.UtcNow,
                IpAddress = null,
                Platform = null
            };
            schemaContext.LoginAttempts.Add(successAttempt);
            await schemaContext.SaveChangesAsync(cancellationToken);

            bool needsFollowUpSave = false;
            if (pendingDeviceContext != null)
            {
                pendingDeviceContext.ActiveAccountId = defaultAccount.UniqueId;
                needsFollowUpSave = true;
            }

            if (verificationLog.AccountId == null)
            {
                verificationLog.AccountId = defaultAccount.UniqueId;
                needsFollowUpSave = true;
            }

            if (needsFollowUpSave)
            {
                await schemaContext.SaveChangesAsync(cancellationToken);
            }

            List<long> failedAttemptIds = await schemaContext.LoginAttempts
                .Join(schemaContext.Memberships,
                    la => la.MembershipId,
                    m => m.UniqueId,
                    (la, m) => new LoginAttemptMembershipQueryRecord { LoginAttempt = la, Membership = m })
                .Where(x => x.Membership.MobileNumberId == mobileUniqueId &&
                            x.LoginAttempt.Outcome == DefaultOutcome &&
                            !x.LoginAttempt.IsSuccess &&
                            !x.LoginAttempt.IsDeleted &&
                            !x.Membership.IsDeleted)
                .Select(x => x.LoginAttempt.Id)
                .ToListAsync(cancellationToken);

            if (failedAttemptIds.Count > 0)
            {
                await schemaContext.LoginAttempts
                    .Where(la => failedAttemptIds.Contains(la.Id))
                    .ExecuteDeleteAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            ProtoMembership.Types.CreationStatus newMembershipCreationStatus = newMembership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            List<AccountInfo> accounts =
            [
                new(
                    defaultAccount.UniqueId,
                    newMembership.UniqueId,
                    defaultAccount.AccountType,
                    defaultAccount.IsDefaultAccount,
                    defaultAccount.Status)
            ];

            return BuildMembershipResult(
                newMembership.UniqueId,
                newMembership.DeviceId,
                newMembership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                newMembershipCreationStatus,
                credentialsVersion: 0,
                opaqueKeyVersion: 0,
                accounts: accounts,
                activeAccountId: defaultAccount.UniqueId,
                credentialsAccountId: defaultAccount.UniqueId);
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
                MembershipFailure.CreationFailed(ex));
        }
    }

    private static async Task<Result<MembershipQueryRecord, MembershipFailure>> GetMembershipByVerificationFlowAsync(
        EcliptixSchemaContext schemaContext,
        GetMembershipByVerificationFlowQuery query,
        CancellationToken cancellationToken)
    {
        try
        {
            VerificationFlowEntity? verificationFlow = await schemaContext.VerificationFlows
                .Include(vf => vf.MobileNumber)
                .Where(vf => vf.UniqueId == query.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken);

            if (verificationFlow == null)
            {
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Verification flow not found"));
            }

            MembershipEntity? membership;

            if (verificationFlow.Purpose == OtpVerificationPurpose.SecureKeyRecovery)
            {
                membership = await schemaContext.Memberships
                    .Where(m => m.MobileNumberId == verificationFlow.MobileNumber.UniqueId &&
                                !m.IsDeleted)
                    .OrderByDescending(m => m.CreatedAt)
                    .FirstOrDefaultAsync(cancellationToken);
            }
            else
            {
                membership = await schemaContext.Memberships
                    .Where(m => m.VerificationFlowId == query.VerificationFlowId &&
                                !m.IsDeleted)
                    .FirstOrDefaultAsync(cancellationToken);
            }

            if (membership == null)
            {
                return Result<MembershipQueryRecord, MembershipFailure>.Err(
                    MembershipFailure.NotFound());
            }

            ProtoMembership.Types.CreationStatus creationStatus = membership.CreationStatus switch
            {
                MembershipCreationStatus.OtpVerified => ProtoMembership.Types.CreationStatus.OtpVerified,
                MembershipCreationStatus.SecureKeySet => ProtoMembership.Types.CreationStatus.SecureKeySet,
                MembershipCreationStatus.PassphraseSet => ProtoMembership.Types.CreationStatus.PassphraseSet,
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForMembership(schemaContext, membership.UniqueId);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.DeviceId,
                membership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                creationStatus,
                credentialsOpt.IsSome ? credentialsOpt.Value!.Version : 0,
                credentialsOpt.IsSome ? credentialsOpt.Value!.OpaqueKeyVersion : 0,
                secureKey: credentialsOpt.IsSome ? credentialsOpt.Value!.SecureKey : null,
                maskingKey: credentialsOpt.IsSome ? credentialsOpt.Value!.MaskingKey : null);
        }
        catch (Exception ex)
        {
            return Result<MembershipQueryRecord, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to get membership by verification flow", ex));
        }
    }

    private static async Task<Result<MembershipQueryRecord, MembershipFailure>> GetMembershipByUniqueIdAsync(
        EcliptixSchemaContext schemaContext,
        GetMembershipByUniqueIdQuery query,
        CancellationToken cancellationToken)
    {
        try
        {
            Option<MembershipEntity> membershipOpt =
                await MembershipQueries.GetByUniqueId(schemaContext, query.MembershipUniqueId, cancellationToken);

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
                _ => ProtoMembership.Types.CreationStatus.OtpVerified
            };

            Option<CredentialsRecord> credentialsOpt =
                await AccountSecureKeyAuthQueries.GetCredentialsForMembership(schemaContext, membership.UniqueId);

            return BuildMembershipResult(
                membership.UniqueId,
                membership.DeviceId,
                membership.Status switch
                {
                    MembershipStatus.Active => Membership.Types.ActivityStatus.Active,
                    MembershipStatus.Inactive => Membership.Types.ActivityStatus.Inactive,
                    _ => Membership.Types.ActivityStatus.Active
                },
                creationStatus,
                credentialsOpt.IsSome ? credentialsOpt.Value!.Version : 0,
                credentialsOpt.IsSome ? credentialsOpt.Value!.OpaqueKeyVersion : 0,
                secureKey: credentialsOpt.IsSome ? credentialsOpt.Value!.SecureKey : null,
                maskingKey: credentialsOpt.IsSome ? credentialsOpt.Value!.MaskingKey : null);
        }
        catch (Exception ex)
        {
            return Result<MembershipQueryRecord, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to get membership by unique ID", ex));
        }
    }

    private static async Task<Result<Unit, MembershipFailure>> UpdateMembershipCreationStatusAsync(
        EcliptixSchemaContext schemaContext,
        UpdateMembershipCreationStatusCommand command,
        CancellationToken cancellationToken)
    {
        try
        {
            int rowsAffected = await schemaContext.Memberships
                .Where(m => m.UniqueId == command.MembershipIdentifier && !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.CreationStatus, command.CreationStatus)
                    .SetProperty(m => m.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken);

            if (rowsAffected == 0)
            {
                Log.Warning(
                    "[UPDATE-CREATION-STATUS] Membership not found. MembershipId={MembershipId}",
                    command.MembershipIdentifier);
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.NotFoundById());
            }

            Log.Information(
                "[UPDATE-CREATION-STATUS] Successfully updated membership {MembershipId} to {CreationStatus}",
                command.MembershipIdentifier,
                command.CreationStatus);

            return Result<Unit, MembershipFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to update membership creation status", ex));
        }
    }

    private static async Task<Result<Unit, MembershipFailure>> UpdateMembershipVerificationFlowAsync(
        EcliptixSchemaContext schemaContext, UpdateMembershipVerificationFlowCommand command, CancellationToken cancellationToken)
    {
        await using IDbContextTransaction transaction =
            await schemaContext.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        try
        {
            if (command.Purpose != OtpVerificationPurpose.SecureKeyRecovery ||
                command.FlowStatus != VerificationFlowStatus.Verified)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<Unit, MembershipFailure>.Ok(Unit.Value);
            }

            VerificationFlowEntity? newFlow = await schemaContext.VerificationFlows
                .Include(vf => vf.MobileNumber)
                .Where(vf => vf.UniqueId == command.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken: cancellationToken);

            if (newFlow?.MobileNumber == null)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.ValidationFailed("Verification flow not found or invalid"));
            }

            MembershipEntity? membership = await schemaContext.Memberships
                .Where(m => m.MobileNumberId == newFlow.MobileNumber.UniqueId && !m.IsDeleted)
                .OrderByDescending(m => m.CreatedAt)
                .FirstOrDefaultAsync(cancellationToken: cancellationToken);

            if (membership == null)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.NotFound());
            }

            VerificationFlowEntity? currentFlow = await schemaContext.VerificationFlows
                .Where(vf => vf.UniqueId == membership.VerificationFlowId && !vf.IsDeleted)
                .FirstOrDefaultAsync(cancellationToken: cancellationToken);

            if (currentFlow != null && currentFlow.UpdatedAt >= newFlow.UpdatedAt)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<Unit, MembershipFailure>.Ok(Unit.Value);
            }

            Guid? oldFlowId = membership.VerificationFlowId;

            int rowsAffected = await schemaContext.Memberships
                .Where(m => m.UniqueId == membership.UniqueId &&
                            m.VerificationFlowId == oldFlowId &&
                            !m.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(m => m.VerificationFlowId, newFlow.UniqueId)
                    .SetProperty(m => m.UpdatedAt, DateTimeOffset.UtcNow), cancellationToken: cancellationToken);

            if (rowsAffected == 0)
            {
                await RollbackSilentlyAsync(transaction);
                return Result<Unit, MembershipFailure>.Err(
                    MembershipFailure.UpdateFailed(new Exception("Optimistic concurrency failure")));
            }

            await transaction.CommitAsync(cancellationToken);

            return Result<Unit, MembershipFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            await RollbackSilentlyAsync(transaction);
            return Result<Unit, MembershipFailure>.Err(
                MembershipFailure.PersistorAccess("Failed to update membership verification flow", ex));
        }
    }

    protected override MembershipFailure MapDbException(DbException ex)
    {
        if (ex is PostgresException pgEx)
        {
            return pgEx.SqlState switch
            {
                PostgresErrorCodes.UniqueViolation =>
                    MembershipFailure.AlreadyExists($"Unique constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.ForeignKeyViolation =>
                    MembershipFailure.ValidationFailed($"Foreign key constraint violation: {pgEx.MessageText}"),
                PostgresErrorCodes.DeadlockDetected => MembershipFailure.DatabaseError(pgEx),
                PostgresErrorCodes.QueryCanceled => MembershipFailure.Timeout(pgEx),
                _ => MembershipFailure.DatabaseError(pgEx)
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
