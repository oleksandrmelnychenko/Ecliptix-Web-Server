using System.Security.Cryptography;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Domain.Memberships.ActorEvents.Account;
using Ecliptix.Domain.Memberships.ActorEvents.Common;
using Ecliptix.Domain.Memberships.ActorEvents.Logout;
using Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;
using Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Configuration;
using Ecliptix.Utilities.Failures.Sodium;
using Microsoft.Extensions.Options;
using ByteString = Google.Protobuf.ByteString;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteResponse;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitResponse;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteResponse;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitResponse;

namespace Ecliptix.Domain.Memberships.WorkerActors;

internal sealed class PendingSignInState : IDisposable
{
    public required Guid MembershipId { get; init; }
    public required Guid MobileNumberId { get; init; }
    public required string MobileNumber { get; init; }
    public required Membership.Types.ActivityStatus ActivityStatus { get; init; }
    public required Membership.Types.CreationStatus CreationStatus { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required byte[] ServerMac { get; init; }
    public List<AccountInfo>? AvailableAccounts { get; init; }
    public Guid? ActiveAccountId { get; init; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(ServerMac);
    }
}

public sealed class MembershipActor : ReceivePersistentActor
{
    private const string PersistenceIdValue = "membership-actor";
    private static readonly TimeSpan PendingPasswordRecoveryTimeout = TimeSpan.FromMinutes(15);

    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _membershipPersistor;
    private readonly IActorRef _accountPersistor;
    private readonly IActorRef _passwordRecoveryPersistor;
    private readonly IOpaqueProtocolService _opaqueProtocolService;
    private readonly IMasterKeyService _masterKeyService;
    private readonly IOptionsMonitor<SecurityConfiguration> _securityConfig;

    private readonly Dictionary<uint, PendingSignInState> _pendingSignIns = new(capacity: 8);

    private readonly Dictionary<Guid, byte[]> _pendingMaskingKeys = new(capacity: 8);
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

        Command<SaveSnapshotSuccess>(_ =>
            Log.Info("[MEMBERSHIP-SNAPSHOT] ✅ Snapshot saved successfully at sequence {0}", LastSequenceNr));

        Command<SaveSnapshotFailure>(failure =>
        {
            Log.Error(failure.Cause, "[MEMBERSHIP-SNAPSHOT] ❌ Failed to save snapshot at sequence {0}",
                LastSequenceNr);
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

    private async Task HandleCompleteRegistrationRecord(CompleteRegistrationRecordActorEvent @event)
    {
        IActorRef replyTo = Sender;

        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out byte[]? maskingKey))
        {
            replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed(
                    "No masking key found for membership during registration completion")));
            return;
        }

        byte[] maskingKeyCopy = maskingKey.AsSpan().ToArray();

        // Step 1: Create default account FIRST (master key splitting needs it)
        Result<AccountCreationResult, AccountFailure> accountResult =
            await _accountPersistor.Ask<Result<AccountCreationResult, AccountFailure>>(
                new CreateDefaultAccountEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (accountResult.IsErr)
        {
            RemovePendingMaskingKey(@event.MembershipIdentifier);
            replyTo.Tell(
                Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                    accountResult.UnwrapErr()));
            return;
        }

        AccountCreationResult accountInfo = accountResult.Unwrap();
        Guid defaultAccountId = accountInfo.Accounts.First(a => a.IsDefault).AccountId;

        // Step 2: Store account credentials (registration record + masking key)
        UpdateAccountSecureKeyEvent updateEvent = new(
            @event.MembershipIdentifier,
            @event.PeerRegistrationRecord,
            maskingKeyCopy,
            AccountId: defaultAccountId,
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

        // Step 2.5: Update membership creation status to SecureKeySet
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
                "MembershipId={MembershipId}, Error={Error}. " +
                "Credentials ARE saved, so not failing registration. Status will be fixed by migration/cleanup.",
                @event.MembershipIdentifier, statusUpdateResult.UnwrapErr().Message);
        }

        // Step 3: Split master key into Shamir shares (now account has credentials)
        Log.Info("[REGISTRATION-MASTER-KEY] Splitting master key into Shamir shares for MembershipId: {0}", @event.MembershipIdentifier);

        Result<dynamic, FailureBase> splitResult = await _masterKeyService.SplitAndStoreMasterKeyAsync(
            @event.MasterKey,
            @event.MembershipIdentifier);

        if (splitResult.IsErr)
        {
            RemovePendingMaskingKey(@event.MembershipIdentifier);
            Log.Error("[REGISTRATION-MASTER-KEY] Failed to split master key for MembershipId: {MembershipId}, Error: {Error}",
                @event.MembershipIdentifier, splitResult.UnwrapErr().Message);
            replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Err(
                AccountFailure.ValidationFailed($"Failed to store master key: {splitResult.UnwrapErr().Message}")));
            return;
        }

        RemovePendingMaskingKey(@event.MembershipIdentifier);

        int accountCount = accountInfo.Accounts.Count;
        List<Protobuf.Account.Account> availableAccounts = new(accountCount);
        for (int i = 0; i < accountCount; i++)
        {
            AccountInfo a = accountInfo.Accounts[i];
            availableAccounts.Add(new Protobuf.Account.Account
            {
                UniqueIdentifier = Helpers.GuidToByteString(a.AccountId),
                MembershipIdentifier = Helpers.GuidToByteString(a.MembershipId),
                AccountType = a.Type,
                AccountName = a.Name,
                Status = a.Status,
                IsDefaultAccount = a.IsDefault
            });
        }

        replyTo.Tell(Result<OprfRegistrationCompleteResponse, AccountFailure>.Ok(
            new OprfRegistrationCompleteResponse
            {
                Result = OprfRegistrationCompleteResponse.Types.RegistrationResult.Succeeded,
                Message = "Registration completed successfully.",
                SessionKey = ByteString.Empty,
                AvailableAccounts = { availableAccounts },
                ActiveAccount = availableAccounts[0]
            }));
    }

    private async Task HandleCompleteRecoverySecureKeyEvent(OprfCompleteRecoverySecureKeyEvent @event)
    {
        IActorRef replyTo = Sender;
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Log.Info(
            "[PASSWORD-RECOVERY-COMPLETE] Starting password recovery completion for membership {MembershipId}",
            @event.MembershipIdentifier);

        if (!_pendingRecoveryTimestamps.TryGetValue(@event.MembershipIdentifier, out DateTimeOffset initTimestamp))
        {
            Log.Warning("[PASSWORD-RECOVERY-COMPLETE] No recovery session found for membership {0}",
                @event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.TokenInvalid(
                    "No password recovery session found. Please restart the password recovery process.")));
            return;
        }

        TimeSpan elapsed = now - initTimestamp;
        if (elapsed > PendingPasswordRecoveryTimeout)
        {
            Log.Warning(
                "[PASSWORD-RECOVERY-COMPLETE] Password recovery timeout exceeded for membership {MembershipId}. Elapsed: {Elapsed}, Max: {Max}",
                @event.MembershipIdentifier, elapsed, PendingPasswordRecoveryTimeout);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.TokenExpired(
                    "Password recovery session expired. Please restart the password recovery process.")));
            return;
        }

        Log.Info(
            "[PASSWORD-RECOVERY-COMPLETE] Recovery session validated. MembershipId: {MembershipId}, SessionAge: {Elapsed}",
            @event.MembershipIdentifier, elapsed);

        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out byte[]? maskingKey))
        {
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.TokenInvalid(
                    "No masking key found for membership during recovery completion")));
            return;
        }

        byte[] maskingKeyCopy = maskingKey.AsSpan().ToArray();

        Log.Info("[PASSWORD-RECOVERY-MASTER-KEY] Splitting new master key into Shamir shares (replacing old shares) for MembershipId: {MembershipId}", @event.MembershipIdentifier);

        Result<dynamic, FailureBase> splitResult = await _masterKeyService.SplitAndStoreMasterKeyAsync(
            @event.MasterKey,
            @event.MembershipIdentifier,
            allowOverwrite: true);

        if (splitResult.IsErr)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            Log.Error("[PASSWORD-RECOVERY-MASTER-KEY] Failed to split master key for MembershipId: {MembershipId}, Error: {Error}",
                @event.MembershipIdentifier, splitResult.UnwrapErr().Message);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.TokenInvalid($"Failed to store master key: {splitResult.UnwrapErr().Message}")));
            return;
        }

        if (!_pendingSessionKeys.TryGetValue(@event.MembershipIdentifier,
                out SodiumSecureMemoryHandle? sessionKeyHandle))
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.TokenInvalid(
                    "No session key found for membership during recovery completion")));
            return;
        }

        if (sessionKeyHandle.IsInvalid)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.TokenInvalid("Session key handle is invalid")));
            return;
        }

        Log.Info("[PASSWORD-RECOVERY-COMPLETE] New master key shares created during password recovery for membership {0}",
            @event.MembershipIdentifier);

        UpdateAccountSecureKeyEvent updateEvent = new(
            @event.MembershipIdentifier,
            @event.PeerRecoveryRecord,
            maskingKeyCopy,
            AccountId: null,
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
                Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>
                    .Err(PasswordRecoveryFailure.FromAccount(persistorResult.UnwrapErr())));
            return;
        }

        ClearPendingRecoverySession(@event.MembershipIdentifier);

        Result<Unit, PasswordRecoveryFailure> expireResult =
            await _passwordRecoveryPersistor.Ask<Result<Unit, PasswordRecoveryFailure>>(
                new ExpirePasswordRecoveryFlowsEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (expireResult.IsErr)
        {
            Log.Warning("Failed to expire password recovery flows for membership {0}: {1}",
                @event.MembershipIdentifier, expireResult.UnwrapErr().Message);
        }

        replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, PasswordRecoveryFailure>.Ok(
            new OprfRecoverySecretKeyCompleteResponse { Message = "Recovery secret key completed successfully." }));
    }

    private async Task HandleInitRecoveryRequestEvent(OprfInitRecoverySecureKeyEvent @event)
    {
        IActorRef replyTo = Sender;
        Log.Info(
            "[PASSWORD-RECOVERY-INIT] Starting password recovery init for membership {0}",
            @event.MembershipIdentifier);

        Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure> flowValidation =
            await _passwordRecoveryPersistor.Ask<Result<PasswordRecoveryFlowValidation, PasswordRecoveryFailure>>(
                new ValidatePasswordRecoveryFlowEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (flowValidation.IsErr)
        {
            Log.Error("[PASSWORD-RECOVERY-INIT] Flow validation failed for membership {0}: {1}",
                @event.MembershipIdentifier, flowValidation.UnwrapErr().Message);
            replyTo.Tell(
                Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>.Err(
                    flowValidation.UnwrapErr()));
            return;
        }

        PasswordRecoveryFlowValidation validation = flowValidation.Unwrap();
        if (!validation.IsValid)
        {
            Log.Warning(
                "[PASSWORD-RECOVERY-INIT] Invalid recovery flow for membership {MembershipId}. OTP verification required.",
                @event.MembershipIdentifier);

            string errorMessage = _localizationProvider.Localize(
                VerificationFlowMessageKeys.PasswordRecoveryOtpRequired,
                @event.CultureName);

            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.ValidationFailed(errorMessage)));
            return;
        }

        Log.Info(
            "[PASSWORD-RECOVERY-INIT] Recovery flow validated. MembershipId: {MembershipId}, FlowId: {FlowId}",
            @event.MembershipIdentifier, validation.FlowId);

        if (_pendingRecoveryTimestamps.TryGetValue(@event.MembershipIdentifier, out DateTimeOffset existingTimestamp))
        {
            TimeSpan elapsed = DateTimeOffset.UtcNow - existingTimestamp;
            if (elapsed < PendingPasswordRecoveryTimeout)
            {
                int remainingSeconds = (int)(PendingPasswordRecoveryTimeout - elapsed).TotalSeconds;
                Log.Warning(
                    "Password recovery already in progress for membership {MembershipId}. Time remaining: {Seconds}s",
                    @event.MembershipIdentifier, remainingSeconds);
                replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>.Err(
                    PasswordRecoveryFailure.InternalError(
                        $"A password reset is already in progress. Please wait {remainingSeconds} seconds before trying again.")));
                return;
            }

            Log.Info(
                "Previous password recovery attempt expired for membership {MembershipId}. Cleaning up and allowing new attempt.",
                @event.MembershipIdentifier);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
        }

        (byte[] oprfResponse, byte[] maskingKey, byte[] sessionKey) =
            _opaqueProtocolService.ProcessOprfRequestWithSessionKey(@event.OprfRequest);

        string sessionKeyFingerprint = Convert.ToHexString(SHA256.HashData(sessionKey))[..16];
        Log.Info(
            "[PASSWORD-RECOVERY-INIT-EXPORTKEY] OPAQUE export_key derived during password recovery INIT. MembershipId: {MembershipId}, ExportKeyFingerprint: {ExportKeyFingerprint}",
            @event.MembershipIdentifier, sessionKeyFingerprint);

        if (!TryValidateSessionKey(sessionKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey);
            CryptographicOperations.ZeroMemory(sessionKey);
            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>.Err(
                PasswordRecoveryFailure.InternalError("Failed to process session key securely")));
            return;
        }

        byte[] maskingKeyCopy = maskingKey.AsSpan().ToArray();
        byte[] sessionKeyCopy = (byte[])sessionKey.Clone();
        CryptographicOperations.ZeroMemory(sessionKey);

        Result<Option<Guid>, AccountFailure> accountResult =
            await _accountPersistor.Ask<Result<Option<Guid>, AccountFailure>>(
                new GetDefaultAccountIdEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        ByteString? accountUniqueId = null;
        if (accountResult.IsOk && accountResult.Unwrap().HasValue)
        {
            accountUniqueId = Helpers.GuidToByteString(accountResult.Unwrap().Value);
        }

        OprfRecoverySecureKeyInitResponse response = new()
        {
            Membership = new Membership
            {
                UniqueIdentifier = Helpers.GuidToByteString(@event.MembershipIdentifier),
                Status = Membership.Types.ActivityStatus.Active,
                CreationStatus = Membership.Types.CreationStatus.SecureKeySet,
                AccountUniqueIdentifier = accountUniqueId
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OprfRecoverySecureKeyInitResponse.Types.RecoveryResult.Succeeded
        };

        Log.Info(
            "[PASSWORD-RECOVERY-INIT] OPRF generated for membership {MembershipId}. Credentials stored in pending state (persisted).",
            @event.MembershipIdentifier);

        PersistAsync(
            new RecoverySessionStartedEvent(
                @event.MembershipIdentifier,
                maskingKeyCopy,
                sessionKeyCopy,
                DateTimeOffset.UtcNow),
            evt =>
            {
                Apply(evt);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, PasswordRecoveryFailure>.Ok(response));
            });
    }

    private async Task HandleGenerateMembershipOprfRegistrationRecord(
        GenerateMembershipOprfRegistrationRequestEvent @event)
    {
        IActorRef replyTo = Sender;
        (byte[] oprfResponse, byte[] maskingKey) = _opaqueProtocolService.ProcessOprfRequest(@event.OprfRequest);

        OprfRegistrationInitResponse response = new()
        {
            Membership = new Membership
            {
                UniqueIdentifier = Helpers.GuidToByteString(@event.MembershipIdentifier),
                Status = Membership.Types.ActivityStatus.Inactive,
                CreationStatus = Membership.Types.CreationStatus.OtpVerified
            },
            PeerOprf = ByteString.CopyFrom(oprfResponse),
            Result = OprfRegistrationInitResponse.Types.UpdateResult.Succeeded
        };

        Log.Info("[MEMBERSHIP-PERSIST] Persisting RegistrationMaskingKeyStoredEvent for MembershipId: {0}. Current LastSequenceNr: {1}",
            @event.MembershipIdentifier, LastSequenceNr);

        PersistAsync(
            new RegistrationMaskingKeyStoredEvent(@event.MembershipIdentifier, maskingKey),
            evt =>
            {
                Apply(evt);
                Log.Info("[MEMBERSHIP-PERSIST] ✅ RegistrationMaskingKeyStoredEvent persisted successfully. New LastSequenceNr: {0}",
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
                        Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                        Message = message
                    }));
                return;
            }

            replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Err(failure));
            return;
        }

        MembershipQueryRecord record = persistorResult.Unwrap();

        Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> initiateSignInResult =
            _opaqueProtocolService.InitiateSignIn(
                @event.OpaqueSignInInitRequest,
                new MembershipOpaqueQueryRecord(@event.MobileNumber, record.SecureKey, record.MaskingKey));

        if (initiateSignInResult.IsErr)
        {
            string message = _localizationProvider.Localize(
                VerificationFlowMessageKeys.InvalidCredentials,
                @event.CultureName);

            replyTo.Tell(Result<OpaqueSignInInitResponse, MembershipFailure>.Ok(
                new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials,
                    Message = message
                }));
            return;
        }

        (OpaqueSignInInitResponse response, byte[] serverMac) = initiateSignInResult.Unwrap();

        List<AccountInfo> accountsCopy = record.AvailableAccounts.Select(CloneAccountInfo).ToList();

        PersistAsync(
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
                record.ActiveAccountId),
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
                    Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials
                }));
            return;
        }

        Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
            opaqueResult =
                _opaqueProtocolService.CompleteSignIn(@event.Request, state.ServerMac);

        if (opaqueResult.IsErr)
        {
            RemovePendingSignIn(@event.ConnectId);
            replyTo.Tell(Result<OpaqueSignInFinalizeResponse, MembershipFailure>.Ok(
                new OpaqueSignInFinalizeResponse
                {
                    Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials
                }));
            return;
        }

        (SodiumSecureMemoryHandle sessionKeyHandle, OpaqueSignInFinalizeResponse finalizeResponse) =
            opaqueResult.Unwrap();

        Result<byte[], SodiumFailure> sessionKeyBytesResult = sessionKeyHandle.ReadBytes(sessionKeyHandle.Length);
        if (sessionKeyBytesResult.IsOk)
        {
            byte[] sessionKeyBytes = sessionKeyBytesResult.Unwrap();
            string sessionKeyFingerprint = Convert.ToHexString(SHA256.HashData(sessionKeyBytes))[..16];
            Log.Info(
                "[SERVER-OPAQUE-EXPORTKEY] OPAQUE export_key (session key) derived. MembershipId: {0}, SessionKeyFingerprint: {1}",
                state.MembershipId, sessionKeyFingerprint);
            CryptographicOperations.ZeroMemory(sessionKeyBytes);
        }

        if (finalizeResponse.Result == OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded &&
            !sessionKeyHandle.IsInvalid)
        {
            await EnsureMasterKeySharesExist(sessionKeyHandle, state.MembershipId);
        }

        RemovePendingSignIn(@event.ConnectId);

        finalizeResponse.Membership = new Membership
        {
            UniqueIdentifier = Helpers.GuidToByteString(state.MembershipId),
            Status = state.ActivityStatus,
            CreationStatus = state.CreationStatus,
            AccountUniqueIdentifier = state.ActiveAccountId.HasValue
                ? Helpers.GuidToByteString(state.ActiveAccountId.Value)
                : ByteString.Empty
        };

        if (state.AvailableAccounts != null && state.AvailableAccounts.Any())
        {
            List<Protobuf.Account.Account> availableAccounts = state.AvailableAccounts.Select(a =>
                new Protobuf.Account.Account
                {
                    UniqueIdentifier = Helpers.GuidToByteString(a.AccountId),
                    MembershipIdentifier = Helpers.GuidToByteString(a.MembershipId),
                    AccountType = a.Type,
                    AccountName = a.Name,
                    Status = a.Status,
                    IsDefaultAccount = a.IsDefault
                }).ToList();

            finalizeResponse.AvailableAccounts.AddRange(availableAccounts);

            if (state.ActiveAccountId.HasValue)
            {
                finalizeResponse.ActiveAccount = availableAccounts.FirstOrDefault(a =>
                    Helpers.FromByteStringToGuid(a.UniqueIdentifier) == state.ActiveAccountId.Value);
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
            ServerMac = (byte[])evt.ServerMac.Clone(),
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
        StoreMaskingKey(evt.MembershipId, evt.MaskingKey);
    }

    private void Apply(RegistrationMaskingKeyRemovedEvent evt)
    {
        if (_pendingMaskingKeys.TryGetValue(evt.MembershipId, out byte[]? maskingKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey);
            _pendingMaskingKeys.Remove(evt.MembershipId);
        }
    }

    private void Apply(RecoverySessionStartedEvent evt)
    {
        StoreMaskingKey(evt.MembershipId, evt.MaskingKey);
        StoreSessionKey(evt.MembershipId, evt.SessionKey);
        _pendingRecoveryTimestamps[evt.MembershipId] = evt.StartedAt;
    }

    private void Apply(RecoverySessionClearedEvent evt)
    {
        if (_pendingMaskingKeys.TryGetValue(evt.MembershipId, out byte[]? maskingKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey);
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
                kvp.Value.ServerMac.AsSpan().ToArray(),
                accountsCopy,
                kvp.Value.ActiveAccountId));
        }

        List<RegistrationMaskingKeyStoredEvent> pendingMaskingKeys = new(_pendingMaskingKeys.Count);
        foreach (KeyValuePair<Guid, byte[]> kvp in _pendingMaskingKeys)
        {
            pendingMaskingKeys.Add(new RegistrationMaskingKeyStoredEvent(
                kvp.Key,
                kvp.Value.AsSpan().ToArray()));
        }

        List<RecoverySessionSnapshot> recoverySessions = new();
        foreach ((Guid membershipId, DateTimeOffset startedAt) in _pendingRecoveryTimestamps)
        {
            if (_pendingSessionKeys.TryGetValue(membershipId, out SodiumSecureMemoryHandle? handle))
            {
                byte[]? sessionKeyBytes = TryReadSessionKeyBytes(handle);
                if (sessionKeyBytes != null)
                {
                    recoverySessions.Add(new RecoverySessionSnapshot(membershipId, sessionKeyBytes, startedAt));
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
            source.Name,
            source.IsDefault,
            source.Status);
    }

    private void StoreMaskingKey(Guid membershipId, byte[] source)
    {
        if (_pendingMaskingKeys.TryGetValue(membershipId, out byte[]? existing))
        {
            CryptographicOperations.ZeroMemory(existing);
        }

        byte[] copy = new byte[source.Length];
        Buffer.BlockCopy(source, 0, copy, 0, source.Length);
        _pendingMaskingKeys[membershipId] = copy;
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
            Serilog.Log.Error("Failed to allocate secure memory for session key validation: {0}",
                allocateResult.UnwrapErr().Message);
            return false;
        }

        using SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
        Result<Unit, SodiumFailure> writeResult = handle.Write(sessionKey);

        if (writeResult.IsErr)
        {
            Serilog.Log.Error("Failed to write session key to secure memory during validation: {0}",
                writeResult.UnwrapErr().Message);
            return false;
        }

        return true;
    }

    private static byte[]? TryReadSessionKeyBytes(SodiumSecureMemoryHandle handle)
    {
        Result<byte[], SodiumFailure> readResult = handle.ReadBytes(handle.Length);
        if (readResult.IsErr)
        {
            Serilog.Log.Error("Failed to read session key bytes for snapshot: {0}", readResult.UnwrapErr().Message);
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

        foreach (byte[] maskingKey in _pendingMaskingKeys.Values)
        {
            CryptographicOperations.ZeroMemory(maskingKey);
        }

        _pendingMaskingKeys.Clear();

        foreach (SodiumSecureMemoryHandle sessionKeyHandle in _pendingSessionKeys.Values)
        {
            sessionKeyHandle.Dispose();
        }

        _pendingSessionKeys.Clear();
        _pendingRecoveryTimestamps.Clear();
    }

    private async Task EnsureMasterKeySharesExist(SodiumSecureMemoryHandle sessionKeyHandle, Guid membershipId)
    {
        Result<bool, FailureBase> ensureResult = await _masterKeyService.EnsureMasterKeyExistsAsync(membershipId);

        if (ensureResult.IsErr)
        {
            Log.Error(
                "[MASTER-KEY-ENSURE] Failed to ensure master key shares exist for membership {0}: {1}",
                membershipId,
                ensureResult.UnwrapErr().Message);
            return;
        }

        Log.Debug("[MASTER-KEY-ENSURE] Master key shares verified for membership {0}", membershipId);
    }

}

public record UpdateAccountSecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] SecureKey,
    byte[] MaskingKey,
    Guid? AccountId = null,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record GenerateMembershipOprfRegistrationRequestEvent(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record CompleteRegistrationRecordActorEvent(
    Guid MembershipIdentifier,
    byte[] PeerRegistrationRecord,
    byte[] MasterKey,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record OprfInitRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    string CultureName,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record OprfCompleteRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] PeerRecoveryRecord,
    byte[] MasterKey,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);

internal record CleanupExpiredPendingSignIns;

internal record CleanupExpiredPasswordRecovery;
