using System.Security.Cryptography;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;
using Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.Membership.PersistenceModels;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Services.Security;
using Ecliptix.OPAQUE.Server;
using Ecliptix.Protobuf.Membership;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Failures.Sodium;
using Microsoft.Extensions.Options;
using Npgsql;
using ByteString = Google.Protobuf.ByteString;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRecoveryCompleteResponse;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Membership.OpaqueRecoveryInitResponse;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteResponse;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitResponse;

namespace Ecliptix.IdentityAccess.Domain.Memberships.WorkerActors.Membership;

internal sealed class PendingSignInState : IDisposable
{
    public required Guid MembershipId { get; init; }
    public required Guid MobileNumberId { get; init; }
    public required string MobileNumber { get; init; }
    public required ProtoMembership.Types.ActivityStatus ActivityStatus { get; init; }
    public required ProtoMembership.Types.CreationStatus CreationStatus { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required byte[]? ServerMac { get; init; }
    public required int OpaqueKeyVersion { get; init; }
    public List<AccountInfo>? AvailableAccounts { get; init; }
    public Guid? ActiveAccountId { get; init; }

    public void Dispose()
    {
        if (ServerMac is not null)
        {
            CryptographicOperations.ZeroMemory(ServerMac);
        }
    }
}

internal sealed class PendingOpaqueContext
{
    public required byte[] AccountIdBytes { get; init; }
    public required int OpaqueKeyVersion { get; init; }
}

public sealed class MembershipActor : ReceivePersistentActor
{
    private const string PersistenceIdValue = "membership-actor-v2";
    private static readonly TimeSpan PendingPasswordRecoveryTimeout = TimeSpan.FromMinutes(15);
    private const int OpaqueAccountIdLength = 16;
    private const int OpaqueMaskingKeyLength = 32;

    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipPersistor;
    private readonly IActorRef _accountPersistor;
    private readonly IActorRef _passwordRecoveryPersistor;
    private readonly IOpaqueProtocolService _opaqueProtocolService;
    private readonly IMasterKeyService _masterKeyService;
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private readonly Dictionary<uint, PendingSignInState> _pendingSignIns = new(capacity: 8);

    private readonly Dictionary<Guid, PendingOpaqueContext> _pendingMaskingKeys = new(capacity: 8);
    private readonly Dictionary<Guid, SodiumSecureMemoryHandle> _pendingSessionKeys = new(capacity: 8);
    private readonly Dictionary<Guid, DateTimeOffset> _pendingRecoveryTimestamps = new(capacity: 8);

    private ICancelable? _cleanupTimer;
    private ICancelable? _passwordRecoveryCleanupTimer;

    public override string PersistenceId => PersistenceIdValue;

    public MembershipActor(IActorRef membershipPersistor,
        IActorRef accountPersistor,
        IActorRef passwordRecoveryPersistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider,
        IMasterKeyService masterKeyService,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        _membershipPersistor = membershipPersistor;
        _accountPersistor = accountPersistor;
        _passwordRecoveryPersistor = passwordRecoveryPersistor;
        _opaqueProtocolService = opaqueProtocolService;
        _localizationProvider = localizationProvider;
        _masterKeyService = masterKeyService;
        _securityConfig = securityConfig;

        CommandAsync<SignInCompleteEvent>(HandleSignInComplete);
        CommandAsync<CleanupExpiredPendingSignIns>(_ => HandleCleanupExpiredPendingSignIns());
        CommandAsync<CleanupExpiredPasswordRecovery>(_ => HandleCleanupExpiredPasswordRecovery());
        CommandAsync<GenerateMembershipOprfRegistrationRequestEvent>(HandleGenerateMembershipOprfRegistrationRecord);
        CommandAsync<CreateMembershipActorEvent>(HandleCreateMembership);
        CommandAsync<SignInMembershipActorEvent>(HandleSignInMembership);
        CommandAsync<CompleteRegistrationRecordActorEvent>(HandleCompleteRegistrationRecord);
        CommandAsync<OprfInitRecoverySecureKeyEvent>(HandleInitRecoveryRequestEvent);
        CommandAsync<OprfCompleteRecoverySecureKeyEvent>(HandleCompleteRecoverySecureKeyEvent);
        CommandAsync<GetMembershipByVerificationFlowEvent>(HandleGetMembershipByVerificationFlow);
        CommandAsync<GetAccountProfileActorEvent>(HandleGetAccountProfile);

        Command<SaveSnapshotSuccess>(_ =>
            Log.Info("[MEMBERSHIP-SNAPSHOT] ✅ Snapshot saved successfully at sequence {0}", LastSequenceNr));

        Command<SaveSnapshotFailure>(failure =>
        {
            Log.Error(failure.Cause, "[MEMBERSHIP-SNAPSHOT] ❌ Failed to save snapshot at sequence {0}",
                LastSequenceNr);
        });

        Command<WriteMessageFailure>(failure =>
        {
            Log.Error(failure.Cause,
                "[MEMBERSHIP-PERSIST] ❌ CRITICAL: Write message failure at sequence {0}. " +
                "PersistenceId: {1}. " +
                "This may indicate a sequence number collision or database constraint violation. " +
                "Actor will restart to recover.",
                LastSequenceNr,
                PersistenceId);

            if (failure.Cause is PostgresException pgEx)
            {
                Log.Error(
                    "[MEMBERSHIP-PERSIST] Postgres SQLSTATE: {0}, Severity: {1}, Message: {2}",
                    pgEx.SqlState, pgEx.Severity, pgEx.MessageText);

                if (pgEx.SqlState == PostgresErrorCodes.UniqueViolation)
                {
                    Log.Warning(
                        "[MEMBERSHIP-PERSIST] Unique constraint violation detected (SQLSTATE 23505). " +
                        "This indicates a sequence number collision during concurrent writes. " +
                        "Current LastSequenceNr: {0}. " +
                        "The actor will restart and reload the correct sequence number from the database.",
                        LastSequenceNr);
                }
            }

            throw new InvalidOperationException(
                $"Persistence failed at sequence {LastSequenceNr} - actor will restart to recover",
                failure.Cause);
        });

        Recover<SnapshotOffer>(offer =>
        {
            Log.Info("[MEMBERSHIP-RECOVERY] Snapshot offered at sequence {0}, snapshot type: {1}",
                offer.Metadata.SequenceNr, offer.Snapshot?.GetType().Name ?? "null");

            if (offer.Snapshot is MembershipActorSnapshot snapshot)
            {
                RestoreSnapshot(snapshot);
                Log.Info("[MEMBERSHIP-RECOVERY] Snapshot restored successfully. PendingSignIns: {0}, PendingMaskingKeys: {1}, RecoverySessions: {2}",
                    _pendingSignIns.Count, _pendingMaskingKeys.Count, _pendingRecoveryTimestamps.Count);
            }
            else
            {
                Log.Warning("[MEMBERSHIP-RECOVERY] Snapshot type mismatch. Expected MembershipActorSnapshot, got {0}",
                    offer.Snapshot?.GetType().Name ?? "null");
            }
        });

        Recover<MembershipActorSnapshot>(snapshot =>
        {
            Log.Info("[MEMBERSHIP-RECOVERY] Direct snapshot recovery at sequence {0}", LastSequenceNr);
            RestoreSnapshot(snapshot);
        });

        Recover<PendingSignInStoredEvent>(evt =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering PendingSignInStoredEvent for ConnectId: {0}, MembershipId: {1} at sequence {2}",
                evt.ConnectId, evt.MembershipId, LastSequenceNr);
            Apply(evt);
        });

        Recover<PendingSignInRemovedEvent>(evt =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering PendingSignInRemovedEvent for ConnectId: {0} at sequence {1}",
                evt.ConnectId, LastSequenceNr);
            Apply(evt);
        });

        Recover<RegistrationMaskingKeyStoredEvent>(evt =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering RegistrationMaskingKeyStoredEvent for MembershipId: {0} at sequence {1}",
                evt.MembershipId, LastSequenceNr);
            Apply(evt);
        });

        Recover<RegistrationMaskingKeyRemovedEvent>(evt =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering RegistrationMaskingKeyRemovedEvent for MembershipId: {0} at sequence {1}",
                evt.MembershipId, LastSequenceNr);
            Apply(evt);
        });

        Recover<RecoverySessionStartedEvent>(evt =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering RecoverySessionStartedEvent for MembershipId: {0} at sequence {1}",
                evt.MembershipId, LastSequenceNr);
            Apply(evt);
        });

        Recover<RecoverySessionClearedEvent>(evt =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering RecoverySessionClearedEvent for MembershipId: {0} at sequence {1}",
                evt.MembershipId, LastSequenceNr);
            Apply(evt);
        });

        Recover<RecoverySessionSnapshot>(snapshot =>
        {
            Log.Debug("[MEMBERSHIP-RECOVERY] Recovering RecoverySessionSnapshot for MembershipId: {0} at sequence {1}",
                snapshot.MembershipId, LastSequenceNr);
            ApplyRecoverySnapshot(snapshot);
        });

        Recover<RecoveryCompleted>(_ =>
        {
            if (_pendingSignIns.Count > 0)
            {
                Log.Warning(
                    "[MEMBERSHIP-RECOVERY] Clearing {0} stale pending sign-ins after restart. " +
                    "OPAQUE ServerMac is ephemeral and becomes invalid after restart. " +
                    "Client will automatically reinitiate sign-in flow.",
                    _pendingSignIns.Count);
                _pendingSignIns.Clear();
            }

            Log.Info("[MEMBERSHIP-RECOVERY] ✅ Recovery completed successfully. LastSequenceNr: {0}, PendingSignIns: {1}, PendingMaskingKeys: {2}, RecoverySessions: {3}",
                LastSequenceNr, _pendingSignIns.Count, _pendingMaskingKeys.Count, _pendingRecoveryTimestamps.Count);
        });
    }

    public static Props Build(IActorRef membershipPersistor,
        IActorRef accountPersistor,
        IActorRef passwordRecoveryPersistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider,
        IMasterKeyService masterKeyService,
        IOptionsMonitor<SecurityConfiguration> securityConfig)
    {
        return Props.Create(() => new MembershipActor(membershipPersistor, accountPersistor,
            passwordRecoveryPersistor, opaqueProtocolService, localizationProvider, masterKeyService, securityConfig));
    }

    protected override void PreStart()
    {
        base.PreStart();
        Log.Info("[MEMBERSHIP-START] MembershipActor starting with PersistenceId: '{0}', Initial LastSequenceNr: {1}",
            PersistenceId, LastSequenceNr);

        MembershipActorSettings settings = _securityConfig.CurrentValue.MembershipActor;

        _cleanupTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            settings.CleanupInterval,
            settings.CleanupInterval,
            Self,
            new CleanupExpiredPendingSignIns(),
            ActorRefs.NoSender);

        _passwordRecoveryCleanupTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            settings.PasswordRecoveryCleanupInterval,
            settings.PasswordRecoveryCleanupInterval,
            Self,
            new CleanupExpiredPasswordRecovery(),
            ActorRefs.NoSender);

        Log.Info("[MEMBERSHIP-START] MembershipActor initialization complete. Waiting for recovery...");
    }

    protected override void PostStop()
    {
        _cleanupTimer?.Cancel();
        _passwordRecoveryCleanupTimer?.Cancel();
        ClearState();
        base.PostStop();
    }

    private async Task HandleGetAccountProfile(GetAccountProfileActorEvent @event)
    {
        IActorRef replyTo = Sender;

        GetAccountProfileActorEvent persistorEvent = new (@event.CurrentAccountId, @event.Criteria, @event.CancellationToken);

        Result<Option<AccountProfileInfo>, AccountFailure> persistorResult = await _accountPersistor
            .Ask<Result<Option<AccountProfileInfo>, AccountFailure>>(
                persistorEvent,
                @event.CancellationToken);

        Result<Option<AccountProfileInfo>, FailureBase> finalResult = persistorResult.Match<Result<Option<AccountProfileInfo>, FailureBase>>(
            ok => Result<Option<AccountProfileInfo>, FailureBase>.Ok(ok),
            err => Result<Option<AccountProfileInfo>, FailureBase>.Err(err)
        );

        replyTo.Tell(new GetAccountProfileResult(finalResult));
    }

    private async Task HandleCompleteRegistrationRecord(CompleteRegistrationRecordActorEvent @event)
    {
        IActorRef replyTo = Sender;

        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-REG-COMPLETE] MembershipId: {0}, RecordLen: {1}, Record: {2}",
                @event.MembershipIdentifier,
                @event.PeerRegistrationRecord?.Length ?? 0,
                @event.PeerRegistrationRecord is { Length: > 0 }
                    ? Convert.ToHexString(@event.PeerRegistrationRecord)
                    : string.Empty);
        }

        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out PendingOpaqueContext? pendingContext))
        {
            replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed(
                    "No pending account id found for membership during registration completion")));
            return;
        }

        Guid? pendingAccountId = TryParseAccountId(pendingContext.AccountIdBytes);
        if (!pendingAccountId.HasValue)
        {
            RemovePendingMaskingKey(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed(
                    "Registration session invalid. Please restart registration.")));
            return;
        }

        Guid accountId = pendingAccountId.Value;
        int opaqueKeyVersion = pendingContext.OpaqueKeyVersion;
        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-REG-COMPLETE] MembershipId: {0}, AccountId: {1}",
                @event.MembershipIdentifier,
                accountId);
        }
        byte[] maskingKeyForStorage = new byte[OpaqueMaskingKeyLength];

        if (@event.PeerRegistrationRecord is null ||
            @event.PeerRegistrationRecord.Length != OpaqueConstants.REGISTRATION_RECORD_LENGTH)
        {
            RemovePendingMaskingKey(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed(
                    $"Registration record must be {OpaqueConstants.REGISTRATION_RECORD_LENGTH} bytes")));
            return;
        }

        UpdateAccountSecureKeyEvent updateEvent = new(
            @event.MembershipIdentifier,
            @event.PeerRegistrationRecord,
            maskingKeyForStorage,
            OpaqueKeyVersion: opaqueKeyVersion,
            AccountId: accountId,
            CancellationToken: @event.CancellationToken);

        Result<AccountSecureKeyUpdateResult, AccountFailure> persistorResult =
            await _accountPersistor.Ask<Result<AccountSecureKeyUpdateResult, AccountFailure>>(updateEvent,
                @event.CancellationToken);

        if (persistorResult.IsErr)
        {
            RemovePendingMaskingKey(@event.MembershipIdentifier);
            replyTo.Tell(
                Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                    persistorResult.UnwrapErr()));
            return;
        }

        Log.Info(
            "[REGISTRATION-STATUS] Updating CreationStatus to SecureKeySet for MembershipId: {0}",
            @event.MembershipIdentifier);

        Result<Unit, MembershipFailure> statusUpdateResult =
            await _membershipPersistor.Ask<Result<Unit, MembershipFailure>>(
                new UpdateMembershipCreationStatusEvent(
                    @event.MembershipIdentifier,
                    MembershipCreationStatus.SecureKeySet,
                    @event.CancellationToken),
                @event.CancellationToken);

        if (statusUpdateResult.IsErr)
        {
            Log.Error(
                "[REGISTRATION-STATUS] Failed to update CreationStatus after credential save. " +
                "MembershipId={0}, Error={1}. " +
                "Credentials ARE saved, so not failing registration. Status will be fixed by migration/cleanup.",
                @event.MembershipIdentifier, statusUpdateResult.UnwrapErr().Message);
        }

        RemovePendingMaskingKey(@event.MembershipIdentifier);

        Result<List<AccountInfo>, AccountFailure> accountsResult =
            await _accountPersistor.Ask<Result<List<AccountInfo>, AccountFailure>>(
                new GetAccountsByMembershipIdEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        List<AccountInfo>? accountsFromDb = accountsResult.IsOk ? accountsResult.Unwrap() : null;
        List<AccountInfo> accounts = accountsFromDb is { Count: > 0 }
            ? accountsFromDb
            : new List<AccountInfo>
            {
                new(
                    accountId,
                    @event.MembershipIdentifier,
                    Protobuf.Account.AccountType.Personal,
                    true,
                    Protobuf.Account.AccountStatus.Active)
            };

        if (accountsResult.IsErr)
        {
            Log.Warning(
                "[REGISTRATION-ACCOUNTS] Failed to load accounts for membership {0}: {1}",
                @event.MembershipIdentifier,
                accountsResult.UnwrapErr().Message);
        }

        int accountCount = accounts.Count;
        List<Protobuf.Account.Account> availableAccounts = new(accountCount);
        for (int i = 0; i < accountCount; i++)
        {
            AccountInfo a = accounts[i];
            availableAccounts.Add(new Protobuf.Account.Account
            {
                AccountId = Helpers.GuidToByteString(a.AccountId),
                MembershipId = Helpers.GuidToByteString(a.MembershipId),
                AccountType = a.Type,
                Status = a.Status,
                IsDefaultAccount = a.IsDefault
            });
        }

        Protobuf.Account.Account activeAccount =
            availableAccounts.FirstOrDefault(a => a.IsDefaultAccount) ?? availableAccounts[0];

        replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Ok(
            new OprfRegistrationCompleteResponse
            {
                Result = OpaqueOperationResult.Succeeded,
                Message = "Registration completed successfully.",
                SessionKey = ByteString.Empty,
                AvailableAccounts = { availableAccounts },
                ActiveAccount = activeAccount
            }));
    }

    private async Task HandleCompleteRecoverySecureKeyEvent(OprfCompleteRecoverySecureKeyEvent @event)
    {
        IActorRef replyTo = Sender;
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Log.Info(
            "[PASSWORD-RECOVERY-COMPLETE] Starting password recovery completion for membership {0}",
            @event.MembershipIdentifier);

        if (!_pendingRecoveryTimestamps.TryGetValue(@event.MembershipIdentifier, out DateTimeOffset initTimestamp))
        {
            Log.Warning("[PASSWORD-RECOVERY-COMPLETE] No recovery session found for membership {0}",
                @event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenInvalid(
                    "No password recovery session found. Please restart the password recovery process.")));
            return;
        }

        TimeSpan elapsed = now - initTimestamp;
        if (elapsed > PendingPasswordRecoveryTimeout)
        {
            Log.Warning(
                "[PASSWORD-RECOVERY-COMPLETE] Password recovery timeout exceeded for membership {0}. Elapsed: {1}, Max: {2}",
                @event.MembershipIdentifier, elapsed, PendingPasswordRecoveryTimeout);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenExpired(
                    "Password recovery session expired. Please restart the password recovery process.")));
            return;
        }

        Log.Info(
            "[PASSWORD-RECOVERY-COMPLETE] Recovery session validated. MembershipId: {0}, SessionAge: {1}",
            @event.MembershipIdentifier, elapsed);

        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out PendingOpaqueContext? pendingContext))
        {
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenInvalid(
                    "No pending account id found for membership during recovery completion")));
            return;
        }

        Guid? accountId = TryParseAccountId(pendingContext.AccountIdBytes);
        if (!accountId.HasValue)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenInvalid(
                    "Recovery session invalid. Please restart the password recovery process.")));
            return;
        }

        if (@event.PeerRecoveryRecord is null ||
            @event.PeerRecoveryRecord.Length != OpaqueConstants.REGISTRATION_RECORD_LENGTH)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenInvalid(
                    $"Recovery record must be {OpaqueConstants.REGISTRATION_RECORD_LENGTH} bytes")));
            return;
        }

        byte[] maskingKeyForStorage = new byte[OpaqueMaskingKeyLength];

        Log.Info("[PASSWORD-RECOVERY] Credentials will be updated. Master key will be derived on next auth. MembershipId: {0}", @event.MembershipIdentifier);

        if (!_pendingSessionKeys.TryGetValue(@event.MembershipIdentifier,
                out SodiumSecureMemoryHandle? sessionKeyHandle))
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenInvalid(
                    "No session key found for membership during recovery completion")));
            return;
        }

        if (sessionKeyHandle.IsInvalid)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.TokenInvalid("Session key handle is invalid")));
            return;
        }

        Log.Info("[PASSWORD-RECOVERY-COMPLETE] New master key shares created during password recovery for membership {0}",
            @event.MembershipIdentifier);

        UpdateAccountSecureKeyEvent updateEvent = new(
            @event.MembershipIdentifier,
            @event.PeerRecoveryRecord,
            maskingKeyForStorage,
            OpaqueKeyVersion: pendingContext.OpaqueKeyVersion,
            AccountId: accountId,
            CancellationToken: @event.CancellationToken);

        Log.Info(
            "[PASSWORD-RECOVERY-COMPLETE] Updating OPAQUE credentials in database for membership {0}",
            @event.MembershipIdentifier);

        Result<AccountSecureKeyUpdateResult, AccountFailure> persistorResult =
            await _accountPersistor.Ask<Result<AccountSecureKeyUpdateResult, AccountFailure>>(updateEvent,
                @event.CancellationToken);

        if (persistorResult.IsErr)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            Log.Error(
                "CRITICAL: Master keys regenerated but password update failed for membership {0}: {1}. User may be locked out!",
                @event.MembershipIdentifier, persistorResult.UnwrapErr().Message);
            replyTo.Tell(
                Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>
                    .Err(SecretKeyRecoveryFailure.FromAccount(persistorResult.UnwrapErr())));
            return;
        }

        ClearPendingRecoverySession(@event.MembershipIdentifier);

        Result<Unit, SecretKeyRecoveryFailure> expireResult =
            await _passwordRecoveryPersistor.Ask<Result<Unit, SecretKeyRecoveryFailure>>(
                new ExpirePasswordRecoveryFlowsEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (expireResult.IsErr)
        {
            Log.Warning("Failed to expire password recovery flows for membership {0}: {1}",
                @event.MembershipIdentifier, expireResult.UnwrapErr().Message);
        }

        replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, SecretKeyRecoveryFailure>.Ok(
            new OprfRecoverySecretKeyCompleteResponse { Message = "Recovery secret key completed successfully." }));
    }

    private async Task HandleInitRecoveryRequestEvent(OprfInitRecoverySecureKeyEvent @event)
    {
        IActorRef replyTo = Sender;
        Log.Info(
            "[PASSWORD-RECOVERY-INIT] Starting password recovery init for membership {0}",
            @event.MembershipIdentifier);

        Result<PasswordRecoveryFlowValidation, SecretKeyRecoveryFailure> flowValidation =
            await _passwordRecoveryPersistor.Ask<Result<PasswordRecoveryFlowValidation, SecretKeyRecoveryFailure>>(
                new ValidatePasswordRecoveryFlowEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (flowValidation.IsErr)
        {
            Log.Error("[PASSWORD-RECOVERY-INIT] Flow validation failed for membership {0}: {1}",
                @event.MembershipIdentifier, flowValidation.UnwrapErr().Message);
            replyTo.Tell(
                Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Err(
                    flowValidation.UnwrapErr()));
            return;
        }

        PasswordRecoveryFlowValidation validation = flowValidation.Unwrap();
        if (!validation.IsValid)
        {
            Log.Warning(
                "[PASSWORD-RECOVERY-INIT] Invalid recovery flow for membership {0}. OTP verification required.",
                @event.MembershipIdentifier);

            string errorMessage = _localizationProvider.Localize(
                VerificationFlowMessageKeys.PasswordRecoveryOtpRequired,
                @event.CultureName);

            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.ValidationFailed(errorMessage)));
            return;
        }

        Log.Info(
            "[PASSWORD-RECOVERY-INIT] Recovery flow validated. MembershipId: {0}, FlowId: {1}",
            @event.MembershipIdentifier, validation.FlowId);

        if (_pendingRecoveryTimestamps.TryGetValue(@event.MembershipIdentifier, out DateTimeOffset existingTimestamp))
        {
            TimeSpan elapsed = DateTimeOffset.UtcNow - existingTimestamp;
            if (elapsed < PendingPasswordRecoveryTimeout)
            {
                int remainingSeconds = (int)(PendingPasswordRecoveryTimeout - elapsed).TotalSeconds;
                Log.Warning(
                    "Password recovery already in progress for membership {0}. Time remaining: {1}s",
                    @event.MembershipIdentifier, remainingSeconds);
                replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Err(
                    SecretKeyRecoveryFailure.InternalError(
                        $"A password reset is already in progress. Please wait {remainingSeconds} seconds before trying again.")));
                return;
            }

            Log.Info(
                "Previous password recovery attempt expired for membership {0}. Cleaning up and allowing new attempt.",
                @event.MembershipIdentifier);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
        }

        Result<Option<Guid>, AccountFailure> accountResult =
            await _accountPersistor.Ask<Result<Option<Guid>, AccountFailure>>(
                new GetDefaultAccountIdEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (accountResult.IsErr)
        {
            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.FromAccount(accountResult.UnwrapErr())));
            return;
        }

        if (!accountResult.Unwrap().IsSome)
        {
            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.ValidationFailed("Default account not found for membership")));
            return;
        }

        Guid accountId = accountResult.Unwrap().Value;

        var (oprfResponse, _, sessionKey, keyVersion) =
            _opaqueProtocolService.ProcessOprfRequestWithSessionKey(@event.OprfRequest, accountId);

        Log.Info(
            "[PASSWORD-RECOVERY-INIT] OPAQUE OPRF response derived during password recovery init. MembershipId: {0}",
            @event.MembershipIdentifier);

        if (!TryValidateSessionKey(sessionKey))
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Err(
                SecretKeyRecoveryFailure.InternalError("Failed to process session key securely")));
            return;
        }

        byte[] accountIdBytes = accountId.ToByteArray();
        byte[] sessionKeyCopy = (byte[])sessionKey.Clone();
        CryptographicOperations.ZeroMemory(sessionKey);

        OprfRecoverySecureKeyInitResponse response = new()
        {
            Membership = new ProtoMembership
            {
                MembershipId = Helpers.GuidToByteString(@event.MembershipIdentifier),
                Status = ProtoMembership.Types.ActivityStatus.Active,
                CreationStatus = ProtoMembership.Types.CreationStatus.SecureKeySet,
                AccountId = Helpers.GuidToByteString(accountId)
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OpaqueOperationResult.Succeeded
        };

        Log.Info(
            "[PASSWORD-RECOVERY-INIT] OPRF generated for membership {0}. Credentials stored in pending state (persisted).",
            @event.MembershipIdentifier);

        Persist(
            new RecoverySessionStartedEvent(
                @event.MembershipIdentifier,
                accountIdBytes,
                sessionKeyCopy,
                DateTimeOffset.UtcNow,
                keyVersion),
            evt =>
            {
                Apply(evt);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, SecretKeyRecoveryFailure>.Ok(response));
            });
    }

    private async Task HandleGenerateMembershipOprfRegistrationRecord(
        GenerateMembershipOprfRegistrationRequestEvent @event)
    {
        IActorRef replyTo = Sender;
        if (@event.OprfRequest is null)
        {
            replyTo.Tell(Result<OprfRegistrationInitResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed("OPRF request cannot be null")));
            return;
        }

        byte[] oprfRequest = @event.OprfRequest!;
        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-REG-INIT] MembershipId: {0}, OprfLen: {1}, Oprf: {2}",
                @event.MembershipIdentifier,
                oprfRequest.Length,
                oprfRequest.Length > 0 ? Convert.ToHexString(oprfRequest) : string.Empty);
        }
        Result<Option<Guid>, AccountFailure> accountResult =
            await _accountPersistor.Ask<Result<Option<Guid>, AccountFailure>>(
                new GetDefaultAccountIdEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (accountResult.IsErr)
        {
            replyTo.Tell(Result<OprfRegistrationInitResponse, AccountFailure>.Err(accountResult.UnwrapErr()));
            return;
        }

        if (!accountResult.Unwrap().IsSome)
        {
            replyTo.Tell(Result<OprfRegistrationInitResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed("Default account not found for membership")));
            return;
        }

        Guid accountId = accountResult.Unwrap().Value;
        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-REG-INIT] MembershipId: {0}, AccountId: {1}",
                @event.MembershipIdentifier,
                accountId);
        }
        var (oprfResponse, _, keyVersion) = _opaqueProtocolService.ProcessOprfRequest(oprfRequest, accountId);
        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-REG-INIT] MembershipId: {0}, OprfResponseLen: {1}, OprfResponse: {2}",
                @event.MembershipIdentifier,
                oprfResponse.Length,
                Convert.ToHexString(oprfResponse));
        }
        byte[] accountIdBytes = accountId.ToByteArray();

        OprfRegistrationInitResponse response = new()
        {
            Membership = new ProtoMembership
            {
                MembershipId = Helpers.GuidToByteString(@event.MembershipIdentifier),
                Status = ProtoMembership.Types.ActivityStatus.Inactive,
                CreationStatus = ProtoMembership.Types.CreationStatus.OtpVerified
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OpaqueOperationResult.Succeeded
        };

        Log.Info("[MEMBERSHIP-PERSIST] Persisting pending account id for MembershipId: {0}. Current LastSequenceNr: {1}",
            @event.MembershipIdentifier, LastSequenceNr);

        Persist(
            new RegistrationMaskingKeyStoredEvent(@event.MembershipIdentifier, accountIdBytes, keyVersion),
            evt =>
            {
                Apply(evt);
                Log.Info("[MEMBERSHIP-PERSIST] ✅ Pending account id persisted successfully. New LastSequenceNr: {0}",
                    LastSequenceNr);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OprfRegistrationInitResponse, AccountFailure>.Ok(response));
            });

        await Task.CompletedTask;
    }

    private async Task HandleCreateMembership(CreateMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, MembershipFailure> operationResult =
            await _membershipPersistor.Ask<Result<MembershipQueryRecord, MembershipFailure>>(@event,
                @event.CancellationToken);

        Result<MembershipQueryRecord, VerificationFlowFailure> convertedResult = operationResult.Match(
            ok => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(ok),
            err => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMembership(err)));

        Sender.Tell(convertedResult);
    }

    private async Task HandleGetMembershipByVerificationFlow(GetMembershipByVerificationFlowEvent @event)
    {
        Result<MembershipQueryRecord, MembershipFailure> operationResult =
            await _membershipPersistor.Ask<Result<MembershipQueryRecord, MembershipFailure>>(@event,
                @event.CancellationToken);

        Result<MembershipQueryRecord, VerificationFlowFailure> convertedResult = operationResult.Match(
            ok => Result<MembershipQueryRecord, VerificationFlowFailure>.Ok(ok),
            err => Result<MembershipQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.FromMembership(err)));

        Sender.Tell(convertedResult);
    }

    private async Task HandleSignInMembership(SignInMembershipActorEvent @event)
    {
        IActorRef replyTo = Sender;

        Result<MembershipQueryRecord, MembershipFailure> persistorResult =
            await _membershipPersistor.Ask<Result<MembershipQueryRecord, MembershipFailure>>(@event,
                @event.CancellationToken);

        if (persistorResult.IsErr)
        {
            MembershipFailure failure = persistorResult.UnwrapErr();

            if (failure.IsUserFacing)
            {
                string message = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.InvalidCredentials,
                    @event.CultureName);

                replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Ok(
                    new OpaqueSignInInitResponse
                    {
                        Result = OpaqueOperationResult.InvalidCredentials,
                        Message = message
                    }));
                return;
            }

            replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Err(failure));
            return;
        }

        MembershipQueryRecord record = persistorResult.Unwrap();
        if (Serilog.Log.IsEnabled(Serilog.Events.LogEventLevel.Debug))
        {
            Serilog.Log.Debug(
                "[OPAQUE-SIGNIN-INIT] MembershipId: {MembershipId}, Mobile: {Mobile}, SecureKeyLen: {SecureKeyLen}, MaskingKeyLen: {MaskingKeyLen}, CredentialsAccountId: {CredentialsAccountId}, ActiveAccountId: {ActiveAccountId}, Accounts: {Accounts}",
                record.UniqueIdentifier,
                @event.MobileNumber,
                record.SecureKey?.Length ?? 0,
                record.MaskingKey?.Length ?? 0,
                record.CredentialsAccountId,
                record.ActiveAccountId,
                record.AvailableAccounts?.Count ?? 0);
        }

        Guid? accountId = ResolveOpaqueAccountId(record);
        if (!accountId.HasValue)
        {
            replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Ok(
                new OpaqueSignInInitResponse
                {
                    Result = OpaqueOperationResult.InvalidCredentials,
                    Message = _localizationProvider.Localize(
                        VerificationFlowMessageKeys.InvalidCredentials,
                        @event.CultureName)
                }));
            return;
        }
        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-SIGNIN-INIT] MembershipId: {0}, ResolvedAccountId: {1}",
                record.UniqueIdentifier,
                accountId.Value);
        }

        if (record.SecureKey is null || record.SecureKey.Length == 0)
        {
            replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Ok(
                new OpaqueSignInInitResponse
                {
                    Result = OpaqueOperationResult.InvalidCredentials,
                    Message = _localizationProvider.Localize(
                        VerificationFlowMessageKeys.InvalidCredentials,
                        @event.CultureName)
                }));
            return;
        }

        byte[] secureKey = record.SecureKey!;
        Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> initiateSignInResult =
            _opaqueProtocolService.InitiateSignIn(
                @event.OpaqueSignInInitRequest,
                new MembershipOpaqueQueryRecord(@event.MobileNumber, secureKey, accountId.Value, record.OpaqueKeyVersion));

        if (initiateSignInResult.IsErr)
        {
            string message = _localizationProvider.Localize(
                VerificationFlowMessageKeys.InvalidCredentials,
                @event.CultureName);

            replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Ok(
                new OpaqueSignInInitResponse
                {
                    Result = OpaqueOperationResult.InvalidCredentials,
                    Message = message
                }));
            return;
        }

        (OpaqueSignInInitResponse response, byte[] serverMac) = initiateSignInResult.Unwrap();
        if (Log.IsDebugEnabled)
        {
            Log.Debug(
                "[OPAQUE-SIGNIN-INIT] MembershipId: {0}, ServerMacLen: {1}, ServerMac: {2}",
                record.UniqueIdentifier,
                serverMac.Length,
                Convert.ToHexString(serverMac));
        }

        List<AccountInfo> availableAccounts = record.AvailableAccounts ?? new List<AccountInfo>();
        List<AccountInfo> accountsCopy = availableAccounts.Select(CloneAccountInfo).ToList();

        Persist(
            new PendingSignInStoredEvent(
                @event.ConnectId,
                record.UniqueIdentifier,
                Guid.NewGuid(),
                @event.MobileNumber,
                record.ActivityStatus,
                record.CreationStatus,
                DateTimeOffset.UtcNow,
                serverMac,
                accountsCopy,
                record.ActiveAccountId,
                record.OpaqueKeyVersion),
            evt =>
            {
                Apply(evt);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Ok(response));
            });
    }

    private async Task HandleSignInComplete(SignInCompleteEvent @event)
    {
        IActorRef replyTo = Sender;

        if (!_pendingSignIns.TryGetValue(@event.ConnectId, out PendingSignInState? state))
        {
            replyTo.Tell(Result<OpaqueSignInFinalizeResponse, MembershipFailure>.Ok(
                new OpaqueSignInFinalizeResponse
                {
                    Result = OpaqueOperationResult.InvalidCredentials
                }));
            return;
        }
        if (state.ServerMac is null)
        {
            Log.Warning(
                "[OPAQUE-SIGNIN-FINAL] Missing server MAC for ConnectId: {0}, MembershipId: {1}",
                @event.ConnectId,
                state.MembershipId);
            RemovePendingSignIn(@event.ConnectId);
            replyTo.Tell(Result<OpaqueSignInFinalizeResponse, MembershipFailure>.Ok(
                new OpaqueSignInFinalizeResponse
                {
                    Result = OpaqueOperationResult.InvalidCredentials
                }));
            return;
        }

        byte[] serverMac = state.ServerMac!;
        if (Log.IsDebugEnabled)
        {
            byte[] clientMacBytes = @event.Request.ClientMac.ToByteArray();
            Log.Debug(
                "[OPAQUE-SIGNIN-FINAL] ConnectId: {0}, MembershipId: {1}, ClientMacLen: {2}, ClientMac: {3}, ServerMacLen: {4}, ServerMac: {5}",
                @event.ConnectId,
                state.MembershipId,
                clientMacBytes.Length,
                clientMacBytes.Length > 0 ? Convert.ToHexString(clientMacBytes) : string.Empty,
                serverMac.Length,
                serverMac.Length > 0 ? Convert.ToHexString(serverMac) : string.Empty);
        }

        Result<(SodiumSecureMemoryHandle SessionKeyHandle, SodiumSecureMemoryHandle MasterKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
            opaqueResult =
                _opaqueProtocolService.CompleteSignInWithMasterKey(@event.Request, serverMac, state.OpaqueKeyVersion);

        if (opaqueResult.IsErr)
        {
            RemovePendingSignIn(@event.ConnectId);
            replyTo.Tell(Result<OpaqueSignInFinalizeResponse, MembershipFailure>.Ok(
                new OpaqueSignInFinalizeResponse
                {
                    Result = OpaqueOperationResult.InvalidCredentials
                }));
            return;
        }

        (SodiumSecureMemoryHandle sessionKeyHandle, SodiumSecureMemoryHandle masterKeyHandle, OpaqueSignInFinalizeResponse finalizeResponse) =
            opaqueResult.Unwrap();

        if (!sessionKeyHandle.IsInvalid)
        {
            Result<byte[], SodiumFailure> sessionKeyBytesResult = sessionKeyHandle.ReadBytes(sessionKeyHandle.Length);
            if (sessionKeyBytesResult.IsOk)
            {
                byte[] sessionKeyBytes = sessionKeyBytesResult.Unwrap();
                CryptographicOperations.ZeroMemory(sessionKeyBytes);
            }
        }
        else
        {
            Log.Warning(
                "[SERVER-OPAQUE-SESSIONKEY] Session key handle is null or invalid. MembershipId: {0}",
                state.MembershipId);
        }

        if (finalizeResponse.Result == OpaqueOperationResult.Succeeded &&
            sessionKeyHandle != null &&
            !sessionKeyHandle.IsInvalid)
        {
            if (state.ActiveAccountId.HasValue)
            {
                await StoreMasterKeyIfNeeded(state.ActiveAccountId.Value, masterKeyHandle);
            }
            else
            {
                Log.Error(
                    "[MASTER-KEY-STORE] ActiveAccountId missing for MembershipId {0}. Master key shares not stored.",
                    state.MembershipId);
                masterKeyHandle?.Dispose();
            }
        }
        else
        {

            masterKeyHandle?.Dispose();
        }

        RemovePendingSignIn(@event.ConnectId);

        finalizeResponse.Membership = new ProtoMembership
        {
            MembershipId = Helpers.GuidToByteString(state.MembershipId),
            Status = state.ActivityStatus,
            CreationStatus = state.CreationStatus,
            AccountId = state.ActiveAccountId.HasValue
                ? Helpers.GuidToByteString(state.ActiveAccountId.Value)
                : ByteString.Empty
        };

        if (state.AvailableAccounts != null && state.AvailableAccounts.Any())
        {
            List<Protobuf.Account.Account> availableAccounts = state.AvailableAccounts.Select(a =>
                new Protobuf.Account.Account
                {
                    AccountId = Helpers.GuidToByteString(a.AccountId),
                    MembershipId = Helpers.GuidToByteString(a.MembershipId),
                    AccountType = a.Type,
                    Status = a.Status,
                    IsDefaultAccount = a.IsDefault
                }).ToList();

            finalizeResponse.AvailableAccounts.AddRange(availableAccounts);

            if (state.ActiveAccountId.HasValue)
            {
                finalizeResponse.ActiveAccount = availableAccounts.FirstOrDefault(a =>
                    Helpers.FromByteStringToGuid(a.AccountId) == state.ActiveAccountId.Value);
            }
        }

        replyTo.Tell(Result<OpaqueSignInFinalizeResponse, MembershipFailure>.Ok(finalizeResponse));
    }

    private Task HandleCleanupExpiredPendingSignIns()
    {
        MembershipActorSettings settings = _securityConfig.CurrentValue.MembershipActor;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset cutoffTime = now - settings.PendingSignInTimeout;

        List<uint> expiredConnections = new(_pendingSignIns.Count);
        foreach (KeyValuePair<uint, PendingSignInState> kvp in _pendingSignIns)
        {
            if (kvp.Value.CreatedAt < cutoffTime)
            {
                expiredConnections.Add(kvp.Key);
            }
        }

        foreach (uint connectId in expiredConnections)
        {
            RemovePendingSignIn(connectId);
        }

        return Task.CompletedTask;
    }

    private Task HandleCleanupExpiredPasswordRecovery()
    {
        MembershipActorSettings settings = _securityConfig.CurrentValue.MembershipActor;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DateTimeOffset cutoffTime = now - settings.PendingPasswordRecoveryTimeout;

        List<Guid> expiredRecoveries = new(_pendingRecoveryTimestamps.Count);
        foreach (KeyValuePair<Guid, DateTimeOffset> kvp in _pendingRecoveryTimestamps)
        {
            if (kvp.Value < cutoffTime)
            {
                expiredRecoveries.Add(kvp.Key);
            }
        }

        foreach (Guid membershipId in expiredRecoveries)
        {
            Log.Info("Cleaning up expired password recovery attempt for membership {0}",
                membershipId);
            ClearPendingRecoverySession(membershipId);
        }

        return Task.CompletedTask;
    }

    private void RemovePendingSignIn(uint connectId)
    {
        if (!_pendingSignIns.ContainsKey(connectId))
        {
            return;
        }

        PersistAsync(new PendingSignInRemovedEvent(connectId), evt =>
        {
            Apply(evt);
            MaybeSaveSnapshot();
        });
    }

    private void RemovePendingMaskingKey(Guid membershipId)
    {
        if (!_pendingMaskingKeys.ContainsKey(membershipId))
        {
            return;
        }

        PersistAsync(new RegistrationMaskingKeyRemovedEvent(membershipId), evt =>
        {
            Apply(evt);
            MaybeSaveSnapshot();
        });
    }

    private void ClearPendingRecoverySession(Guid membershipId)
    {
        bool hasState =
            _pendingMaskingKeys.ContainsKey(membershipId) ||
            _pendingSessionKeys.ContainsKey(membershipId) ||
            _pendingRecoveryTimestamps.ContainsKey(membershipId);

        if (!hasState)
        {
            return;
        }

        PersistAsync(new RecoverySessionClearedEvent(membershipId), evt =>
        {
            Apply(evt);
            MaybeSaveSnapshot();
        });
    }

    private void Apply(PendingSignInStoredEvent evt)
    {
        if (_pendingSignIns.TryGetValue(evt.ConnectId, out PendingSignInState? existing))
        {
            existing.Dispose();
        }

        _pendingSignIns[evt.ConnectId] = new PendingSignInState
        {
            MembershipId = evt.MembershipId,
            MobileNumberId = evt.MobileNumberId,
            MobileNumber = evt.MobileNumber,
            ActivityStatus = evt.ActivityStatus,
            CreationStatus = evt.CreationStatus,
            CreatedAt = evt.CreatedAt,
            ServerMac = evt.ServerMac is null ? null : (byte[])evt.ServerMac.Clone(),
            OpaqueKeyVersion = evt.OpaqueKeyVersion,
            AvailableAccounts = evt.AvailableAccounts?.Select(CloneAccountInfo).ToList(),
            ActiveAccountId = evt.ActiveAccountId
        };
    }

    private void Apply(PendingSignInRemovedEvent evt)
    {
        if (_pendingSignIns.TryGetValue(evt.ConnectId, out PendingSignInState? state))
        {
            state.Dispose();
            _pendingSignIns.Remove(evt.ConnectId);
        }
    }

    private void Apply(RegistrationMaskingKeyStoredEvent evt)
    {
        StoreMaskingKey(evt.MembershipId, evt.MaskingKey, evt.OpaqueKeyVersion);
    }

    private void Apply(RegistrationMaskingKeyRemovedEvent evt)
    {
        if (_pendingMaskingKeys.TryGetValue(evt.MembershipId, out PendingOpaqueContext? maskingKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey.AccountIdBytes);
            _pendingMaskingKeys.Remove(evt.MembershipId);
        }
    }

    private void Apply(RecoverySessionStartedEvent evt)
    {
        StoreMaskingKey(evt.MembershipId, evt.MaskingKey, evt.OpaqueKeyVersion);
        StoreSessionKey(evt.MembershipId, evt.SessionKey);
        _pendingRecoveryTimestamps[evt.MembershipId] = evt.StartedAt;
    }

    private void Apply(RecoverySessionClearedEvent evt)
    {
        if (_pendingMaskingKeys.TryGetValue(evt.MembershipId, out PendingOpaqueContext? maskingKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey.AccountIdBytes);
            _pendingMaskingKeys.Remove(evt.MembershipId);
        }

        if (_pendingSessionKeys.TryGetValue(evt.MembershipId, out SodiumSecureMemoryHandle? sessionKeyHandle))
        {
            sessionKeyHandle.Dispose();
            _pendingSessionKeys.Remove(evt.MembershipId);
        }

        _pendingRecoveryTimestamps.Remove(evt.MembershipId);
    }

    private void ApplyRecoverySnapshot(RecoverySessionSnapshot snapshot)
    {
        StoreSessionKey(snapshot.MembershipId, snapshot.SessionKey);
        _pendingRecoveryTimestamps[snapshot.MembershipId] = snapshot.StartedAt;
        if (_pendingMaskingKeys.TryGetValue(snapshot.MembershipId, out PendingOpaqueContext? context))
        {
            _pendingMaskingKeys[snapshot.MembershipId] = new PendingOpaqueContext
            {
                AccountIdBytes = context.AccountIdBytes,
                OpaqueKeyVersion = snapshot.OpaqueKeyVersion
            };
        }
    }

    private void RestoreSnapshot(MembershipActorSnapshot snapshot)
    {
        ClearState();

        foreach (PendingSignInStoredEvent evt in snapshot.PendingSignIns)
        {
            Apply(evt);
        }

        foreach (RegistrationMaskingKeyStoredEvent evt in snapshot.PendingMaskingKeys)
        {
            Apply(evt);
        }

        foreach (RecoverySessionSnapshot recovery in snapshot.RecoverySessions)
        {
            ApplyRecoverySnapshot(recovery);
        }

        Log.Debug("MembershipActor state restored from snapshot");
    }

    private void MaybeSaveSnapshot()
    {
        MembershipActorSettings settings = _securityConfig.CurrentValue.MembershipActor;
        if (LastSequenceNr == 0 || LastSequenceNr % settings.SnapshotInterval != 0)
        {
            return;
        }

        SaveSnapshot(CreateSnapshot());
    }

    private MembershipActorSnapshot CreateSnapshot()
    {
        List<PendingSignInStoredEvent> pendingSignIns = new(_pendingSignIns.Count);
        foreach (KeyValuePair<uint, PendingSignInState> kvp in _pendingSignIns)
        {
            List<AccountInfo>? accountsCopy = null;
            if (kvp.Value.AvailableAccounts != null)
            {
                int count = kvp.Value.AvailableAccounts.Count;
                accountsCopy = new List<AccountInfo>(count);
                for (int i = 0; i < count; i++)
                {
                    accountsCopy.Add(CloneAccountInfo(kvp.Value.AvailableAccounts[i]));
                }
            }

            pendingSignIns.Add(new PendingSignInStoredEvent(
                kvp.Key,
                kvp.Value.MembershipId,
                kvp.Value.MobileNumberId,
                kvp.Value.MobileNumber,
                kvp.Value.ActivityStatus,
                kvp.Value.CreationStatus,
                kvp.Value.CreatedAt,
                kvp.Value.ServerMac is { } mac ? mac.AsSpan().ToArray() : null,
                accountsCopy,
                kvp.Value.ActiveAccountId,
                kvp.Value.OpaqueKeyVersion));
        }

        List<RegistrationMaskingKeyStoredEvent> pendingMaskingKeys = new(_pendingMaskingKeys.Count);
        foreach (KeyValuePair<Guid, PendingOpaqueContext> kvp in _pendingMaskingKeys)
        {
            pendingMaskingKeys.Add(new RegistrationMaskingKeyStoredEvent(
                kvp.Key,
                kvp.Value.AccountIdBytes.AsSpan().ToArray(),
                kvp.Value.OpaqueKeyVersion));
        }

        List<RecoverySessionSnapshot> recoverySessions = new();
        foreach ((Guid membershipId, DateTimeOffset startedAt) in _pendingRecoveryTimestamps)
        {
            if (_pendingSessionKeys.TryGetValue(membershipId, out SodiumSecureMemoryHandle? handle))
            {
                byte[]? sessionKeyBytes = TryReadSessionKeyBytes(handle);
                if (sessionKeyBytes != null)
                {
                    int opaqueKeyVersion = _pendingMaskingKeys.TryGetValue(membershipId, out PendingOpaqueContext? context)
                        ? context.OpaqueKeyVersion
                        : 1;
                    recoverySessions.Add(new RecoverySessionSnapshot(membershipId, sessionKeyBytes, startedAt, opaqueKeyVersion));
                }
            }
        }

        return new MembershipActorSnapshot(pendingSignIns, pendingMaskingKeys, recoverySessions);
    }

    private static AccountInfo CloneAccountInfo(AccountInfo source)
    {
        return new AccountInfo(
            source.AccountId,
            source.MembershipId,
            source.Type,
            source.IsDefault,
            source.Status);
    }

    private static Guid? ResolveOpaqueAccountId(MembershipQueryRecord record)
    {
        if (record.CredentialsAccountId.HasValue)
        {
            return record.CredentialsAccountId.Value;
        }

        if (record.ActiveAccountId.HasValue)
        {
            return record.ActiveAccountId.Value;
        }

        if (record.AvailableAccounts is { Count: > 0 })
        {
            AccountInfo? defaultAccount = record.AvailableAccounts.FirstOrDefault(a => a.IsDefault);
            return defaultAccount?.AccountId ?? record.AvailableAccounts[0].AccountId;
        }

        return null;
    }

    private static Guid? TryParseAccountId(byte[] pendingAccountIdBytes)
    {
        if (pendingAccountIdBytes.Length != OpaqueAccountIdLength)
        {
            return null;
        }

        try
        {
            Guid accountId = new(pendingAccountIdBytes);
            return accountId == Guid.Empty ? null : accountId;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private void StoreMaskingKey(Guid membershipId, byte[] source, int opaqueKeyVersion)
    {
        if (_pendingMaskingKeys.TryGetValue(membershipId, out PendingOpaqueContext? existing))
        {
            CryptographicOperations.ZeroMemory(existing.AccountIdBytes);
        }

        byte[] copy = new byte[source.Length];
        Buffer.BlockCopy(source, 0, copy, 0, source.Length);
        _pendingMaskingKeys[membershipId] = new PendingOpaqueContext
        {
            AccountIdBytes = copy,
            OpaqueKeyVersion = opaqueKeyVersion
        };
        CryptographicOperations.ZeroMemory(source);
    }

    private void StoreSessionKey(Guid membershipId, byte[] sessionKeyBytes)
    {
        if (_pendingSessionKeys.TryGetValue(membershipId, out SodiumSecureMemoryHandle? existing))
        {
            existing.Dispose();
        }

        Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
            SodiumSecureMemoryHandle.Allocate(sessionKeyBytes.Length);

        if (allocateResult.IsErr)
        {
            Log.Error("Failed to allocate secure memory for session key: {0}", allocateResult.UnwrapErr().Message);
            return;
        }

        SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
        Result<Unit, SodiumFailure> writeResult = handle.Write(sessionKeyBytes);

        if (writeResult.IsErr)
        {
            Log.Error("Failed to write session key to secure memory: {0}", writeResult.UnwrapErr().Message);
            handle.Dispose();
            return;
        }

        _pendingSessionKeys[membershipId] = handle;
        CryptographicOperations.ZeroMemory(sessionKeyBytes);
    }

    private static bool TryValidateSessionKey(byte[] sessionKey)
    {
        Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
            SodiumSecureMemoryHandle.Allocate(sessionKey.Length);

        if (allocateResult.IsErr)
        {
            return false;
        }

        using SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
        Result<Unit, SodiumFailure> writeResult = handle.Write(sessionKey);

        if (writeResult.IsErr)
        {
            return false;
        }

        return true;
    }

    private static byte[]? TryReadSessionKeyBytes(SodiumSecureMemoryHandle handle)
    {
        Result<byte[], SodiumFailure> readResult = handle.ReadBytes(handle.Length);
        if (readResult.IsErr)
        {
            return null;
        }

        return readResult.Unwrap();
    }

    private void ClearState()
    {
        foreach (PendingSignInState state in _pendingSignIns.Values)
        {
            state.Dispose();
        }

        _pendingSignIns.Clear();

        foreach (PendingOpaqueContext context in _pendingMaskingKeys.Values)
        {
            CryptographicOperations.ZeroMemory(context.AccountIdBytes);
        }

        _pendingMaskingKeys.Clear();

        foreach (SodiumSecureMemoryHandle sessionKeyHandle in _pendingSessionKeys.Values)
        {
            sessionKeyHandle.Dispose();
        }

        _pendingSessionKeys.Clear();
        _pendingRecoveryTimestamps.Clear();
    }

    private async Task EnsureMasterKeySharesExist(Guid accountId)
    {
        Result<bool, FailureBase> ensureResult = await _masterKeyService.EnsureMasterKeyExistsAsync(accountId);

        if (ensureResult.IsErr)
        {
            Log.Error(
                "[MASTER-KEY-ENSURE] Failed to ensure master key shares exist for account {0}: {1}",
                accountId,
                ensureResult.UnwrapErr().Message);
            return;
        }

        Log.Debug("[MASTER-KEY-ENSURE] Master key shares verified for account {0}", accountId);
    }

    private async Task StoreMasterKeyIfNeeded(Guid accountId, SodiumSecureMemoryHandle masterKeyHandle)
    {
        try
        {
            if (masterKeyHandle == null || masterKeyHandle.IsInvalid)
            {
                Log.Warning("[MASTER-KEY-STORE] Master key handle is null or invalid for account {0}", accountId);
                return;
            }

            Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(masterKeyHandle.Length);
            if (readResult.IsErr)
            {
                Log.Error("[MASTER-KEY-STORE] Failed to read master key bytes for account {0}: {1}",
                    accountId, readResult.UnwrapErr().Message);
                return;
            }

            byte[] masterKeyBytes = readResult.Unwrap();
            try
            {
                Result<bool, FailureBase> sharesExistResult = await _masterKeyService.CheckSharesExistAsync(accountId);
                if (sharesExistResult.IsErr)
                {
                    Log.Error("[MASTER-KEY-STORE] Failed to check master key shares for account {0}: {1}",
                        accountId, sharesExistResult.UnwrapErr().Message);
                    return;
                }

                bool allowOverwrite = sharesExistResult.Unwrap();

                if (allowOverwrite)
                {
                    Log.Info("[MASTER-KEY-STORE] Rotating OPAQUE master key for account {0}", accountId);
                }
                else
                {
                    Log.Info("[MASTER-KEY-STORE] Storing OPAQUE master key for account {0}", accountId);
                }

                Result<Unit, FailureBase> splitResult = await _masterKeyService.SplitAndStoreMasterKeyAsync(
                    masterKeyBytes, accountId, allowOverwrite);

                if (splitResult.IsErr)
                {
                    Log.Error("[MASTER-KEY-STORE] Failed to split/store master key for account {0}: {1}",
                        accountId, splitResult.UnwrapErr().Message);
                }
                else
                {
                    Log.Info("[MASTER-KEY-STORE] Successfully stored master key shares for account {0}", accountId);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
        finally
        {
            masterKeyHandle?.Dispose();
        }
    }

}
