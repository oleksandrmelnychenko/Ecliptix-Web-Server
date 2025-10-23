using System.Security.Cryptography;
using System.Threading;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Utilities;
using Ecliptix.Domain.Services.Security;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Protobuf.Membership;
using Ecliptix.Utilities.Failures.Sodium;
using Serilog;
using OprfRegistrationCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationCompleteResponse;
using OprfRecoverySecretKeyCompleteResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecretKeyCompleteResponse;
using OprfRecoverySecureKeyInitResponse = Ecliptix.Protobuf.Membership.OpaqueRecoverySecureKeyInitResponse;
using OprfRegistrationInitResponse = Ecliptix.Protobuf.Membership.OpaqueRegistrationInitResponse;
using ByteString = Google.Protobuf.ByteString;

namespace Ecliptix.Domain.Memberships.WorkerActors;

internal sealed class PendingSignInState : IDisposable
{
    public required Guid MembershipId { get; init; }
    public required Guid MobileNumberId { get; init; }
    public required string MobileNumber { get; init; }
    public required Membership.Types.ActivityStatus ActivityStatus { get; init; }
    public required Membership.Types.CreationStatus CreationStatus { get; init; }
    public required DateTime CreatedAt { get; init; }
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
    private const int SnapshotInterval = 100;

    private readonly ILocalizationProvider _localizationProvider;
    private readonly IActorRef _persistor;
    private readonly IOpaqueProtocolService _opaqueProtocolService;
    private readonly IMasterKeyService _masterKeyService;

    private readonly Dictionary<uint, PendingSignInState> _pendingSignIns = new();

    private readonly Dictionary<Guid, byte[]> _pendingMaskingKeys = new();
    private readonly Dictionary<Guid, SodiumSecureMemoryHandle> _pendingSessionKeys = new();
    private readonly Dictionary<Guid, DateTime> _pendingRecoveryTimestamps = new();

    private static readonly TimeSpan PendingSignInTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PendingPasswordRecoveryTimeout = TimeSpan.FromMinutes(10);
    private ICancelable? _cleanupTimer;

    public override string PersistenceId => PersistenceIdValue;

    public MembershipActor(IActorRef persistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider,
        IMasterKeyService masterKeyService)
    {
        _persistor = persistor;
        _opaqueProtocolService = opaqueProtocolService;
        _localizationProvider = localizationProvider;
        _masterKeyService = masterKeyService;

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
            Log.Debug("MembershipActor snapshot saved at sequence {Sequence}", LastSequenceNr));
        Command<SaveSnapshotFailure>(failure =>
        {
            Log.Warning(failure.Cause, "MembershipActor failed to save snapshot at sequence {Sequence}",
                LastSequenceNr);
        });

        Recover<SnapshotOffer>(offer =>
        {
            if (offer.Snapshot is MembershipActorSnapshot snapshot)
            {
                RestoreSnapshot(snapshot);
            }
        });

        Recover<MembershipActorSnapshot>(RestoreSnapshot);
        Recover<PendingSignInStoredEvent>(Apply);
        Recover<PendingSignInRemovedEvent>(Apply);
        Recover<RegistrationMaskingKeyStoredEvent>(Apply);
        Recover<RegistrationMaskingKeyRemovedEvent>(Apply);
        Recover<RecoverySessionStartedEvent>(Apply);
        Recover<RecoverySessionClearedEvent>(Apply);
        Recover<RecoverySessionSnapshot>(ApplyRecoverySnapshot);
        Recover<RecoveryCompleted>(_ =>
            Log.Debug("MembershipActor recovery completed with sequence {Sequence}", LastSequenceNr));
    }

    public static Props Build(IActorRef persistor,
        IOpaqueProtocolService opaqueProtocolService,
        ILocalizationProvider localizationProvider,
        IMasterKeyService masterKeyService)
    {
        return Props.Create(() => new MembershipActor(persistor, opaqueProtocolService,
            localizationProvider, masterKeyService));
    }

    protected override void PreStart()
    {
        base.PreStart();
        _cleanupTimer = Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            TimeSpan.FromMinutes(5),
            TimeSpan.FromMinutes(5),
            Self,
            new CleanupExpiredPendingSignIns(),
            ActorRefs.NoSender);

        Context.System.Scheduler.ScheduleTellRepeatedlyCancelable(
            TimeSpan.FromMinutes(2),
            TimeSpan.FromMinutes(2),
            Self,
            new CleanupExpiredPasswordRecovery(),
            ActorRefs.NoSender);
    }

    protected override void PostStop()
    {
        _cleanupTimer?.Cancel();
        ClearState();
        base.PostStop();
    }

    private async Task HandleCompleteRegistrationRecord(CompleteRegistrationRecordActorEvent @event)
    {
        IActorRef replyTo = Sender;

        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out byte[]? maskingKey))
        {
            replyTo.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(
                    "No masking key found for membership during registration completion")));
            return;
        }

        byte[] maskingKeyCopy = (byte[])maskingKey.Clone();

        UpdateMembershipSecureKeyEvent updateEvent = new(
            @event.MembershipIdentifier,
            @event.PeerRegistrationRecord,
            maskingKeyCopy,
            @event.CancellationToken);

        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent,
                @event.CancellationToken);

        if (persistorResult.IsErr)
        {
            RemovePendingMaskingKey(@event.MembershipIdentifier);
            replyTo.Tell(
                Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(persistorResult.UnwrapErr()));
            return;
        }

        RemovePendingMaskingKey(@event.MembershipIdentifier);

        Result<AccountCreationResult, VerificationFlowFailure> accountResult =
            await _persistor.Ask<Result<AccountCreationResult, VerificationFlowFailure>>(
                new CreateDefaultAccountEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (accountResult.IsErr)
        {
            replyTo.Tell(
                Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Err(accountResult.UnwrapErr()));
            return;
        }

        AccountCreationResult accountInfo = accountResult.Unwrap();

        List<Protobuf.Account.Account> availableAccounts = accountInfo.Accounts.Select(a => new Protobuf.Account.Account
        {
            UniqueIdentifier = Helpers.GuidToByteString(a.AccountId),
            MembershipIdentifier = Helpers.GuidToByteString(a.MembershipId),
            AccountType = a.Type,
            AccountName = a.Name,
            Status = a.Status,
            IsDefaultAccount = a.IsDefault
        }).ToList();

        replyTo.Tell(Result<OprfRegistrationCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRegistrationCompleteResponse
            {
                Result = OprfRegistrationCompleteResponse.Types.RegistrationResult.Succeeded,
                Message = "Registration completed successfully.",
                SessionKey = ByteString.Empty,
                AvailableAccounts = { availableAccounts },
                ActiveAccount = availableAccounts.First()
            }));
    }

    private async Task HandleCompleteRecoverySecureKeyEvent(OprfCompleteRecoverySecureKeyEvent @event)
    {
        IActorRef replyTo = Sender;
        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-COMPLETE] Starting password recovery completion for membership {MembershipId}",
            @event.MembershipIdentifier);

        if (!_pendingRecoveryTimestamps.TryGetValue(@event.MembershipIdentifier, out DateTime initTimestamp))
        {
            Log.Warning("[PASSWORD-RECOVERY-COMPLETE] No recovery session found for membership {MembershipId}",
                @event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(
                    "No password recovery session found. Please restart the password recovery process.")));
            return;
        }

        TimeSpan elapsed = DateTime.UtcNow - initTimestamp;
        if (elapsed > PendingPasswordRecoveryTimeout)
        {
            Log.Warning(
                "[PASSWORD-RECOVERY-COMPLETE] Password recovery timeout exceeded for membership {MembershipId}. Elapsed: {Elapsed}, Max: {Max}",
                @event.MembershipIdentifier, elapsed, PendingPasswordRecoveryTimeout);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(
                    "Password recovery session expired. Please restart the password recovery process.")));
            return;
        }

        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-COMPLETE] Recovery session validated. MembershipId: {MembershipId}, SessionAge: {Elapsed}",
            @event.MembershipIdentifier, elapsed);

        if (!_pendingMaskingKeys.TryGetValue(@event.MembershipIdentifier, out byte[]? maskingKey))
        {
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(
                    "No masking key found for membership during recovery completion")));
            return;
        }

        byte[] maskingKeyCopy = (byte[])maskingKey.Clone();

        if (!_pendingSessionKeys.TryGetValue(@event.MembershipIdentifier,
                out SodiumSecureMemoryHandle? sessionKeyHandle))
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(
                    "No session key found for membership during recovery completion")));
            return;
        }

        if (sessionKeyHandle.IsInvalid)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("Session key handle is invalid")));
            return;
        }

        Result<dynamic, FailureBase> regenerateResult =
            await _masterKeyService.RegenerateMasterKeySharesAsync(
                sessionKeyHandle, @event.MembershipIdentifier);

        if (regenerateResult.IsErr)
        {
            Log.Error(
                "CRITICAL: Failed to regenerate master key shares for membership {MembershipId}: {Error}. Password reset aborted.",
                @event.MembershipIdentifier, regenerateResult.UnwrapErr().Message);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic(
                    "Failed to regenerate encryption keys. Password reset aborted. Please try again.")));
            return;
        }

        Serilog.Log.Information("Master key shares regenerated successfully for membership {MembershipId}",
            @event.MembershipIdentifier);

        UpdateMembershipSecureKeyEvent updateEvent = new(
            @event.MembershipIdentifier,
            @event.PeerRecoveryRecord,
            maskingKeyCopy,
            @event.CancellationToken);

        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-COMPLETE] Updating OPAQUE credentials in database for membership {MembershipId}",
            @event.MembershipIdentifier);

        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(updateEvent,
                @event.CancellationToken);

        if (persistorResult.IsErr)
        {
            ClearPendingRecoverySession(@event.MembershipIdentifier);
            Log.Error(
                "CRITICAL: Master keys regenerated but password update failed for membership {MembershipId}: {Error}. User may be locked out!",
                @event.MembershipIdentifier, persistorResult.UnwrapErr().Message);
            replyTo.Tell(
                Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>
                    .Err(persistorResult.UnwrapErr()));
            return;
        }

        ClearPendingRecoverySession(@event.MembershipIdentifier);

        Result<Unit, VerificationFlowFailure> expireResult =
            await _persistor.Ask<Result<Unit, VerificationFlowFailure>>(
                new ExpirePasswordRecoveryFlowsEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (expireResult.IsErr)
        {
            Log.Warning("Failed to expire password recovery flows for membership {MembershipId}: {Error}",
                @event.MembershipIdentifier, expireResult.UnwrapErr().Message);
        }

        replyTo.Tell(Result<OprfRecoverySecretKeyCompleteResponse, VerificationFlowFailure>.Ok(
            new OprfRecoverySecretKeyCompleteResponse { Message = "Recovery secret key completed successfully." }));
    }

    private async Task HandleInitRecoveryRequestEvent(OprfInitRecoverySecureKeyEvent @event)
    {
        IActorRef replyTo = Sender;
        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-INIT] Starting password recovery init for membership {MembershipId}",
            @event.MembershipIdentifier);

        Result<PasswordRecoveryFlowValidation, VerificationFlowFailure> flowValidation =
            await _persistor.Ask<Result<PasswordRecoveryFlowValidation, VerificationFlowFailure>>(
                new ValidatePasswordRecoveryFlowEvent(@event.MembershipIdentifier, @event.CancellationToken),
                @event.CancellationToken);

        if (flowValidation.IsErr)
        {
            Log.Error("[PASSWORD-RECOVERY-INIT] Flow validation failed for membership {MembershipId}: {Error}",
                @event.MembershipIdentifier, flowValidation.UnwrapErr().Message);
            replyTo.Tell(
                Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(flowValidation.UnwrapErr()));
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

            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Unauthorized(errorMessage)));
            return;
        }

        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-INIT] Recovery flow validated. MembershipId: {MembershipId}, FlowId: {FlowId}",
            @event.MembershipIdentifier, validation.FlowId);

        if (_pendingRecoveryTimestamps.TryGetValue(@event.MembershipIdentifier, out DateTime existingTimestamp))
        {
            TimeSpan elapsed = DateTime.UtcNow - existingTimestamp;
            if (elapsed < PendingPasswordRecoveryTimeout)
            {
                int remainingSeconds = (int)(PendingPasswordRecoveryTimeout - elapsed).TotalSeconds;
                Log.Warning(
                    "Password recovery already in progress for membership {MembershipId}. Time remaining: {Seconds}s",
                    @event.MembershipIdentifier, remainingSeconds);
                replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Generic(
                        $"A password reset is already in progress. Please wait {remainingSeconds} seconds before trying again.")));
                return;
            }

            Serilog.Log.Information(
                "Previous password recovery attempt expired for membership {MembershipId}. Cleaning up and allowing new attempt.",
                @event.MembershipIdentifier);
            ClearPendingRecoverySession(@event.MembershipIdentifier);
        }

        (byte[] oprfResponse, byte[] maskingKey, byte[] sessionKey) =
            _opaqueProtocolService.ProcessOprfRequestWithSessionKey(@event.OprfRequest);

        string sessionKeyFingerprint = Convert.ToHexString(SHA256.HashData(sessionKey))[..16];
        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-INIT-EXPORTKEY] OPAQUE export_key derived during password recovery INIT. MembershipId: {MembershipId}, ExportKeyFingerprint: {ExportKeyFingerprint}",
            @event.MembershipIdentifier, sessionKeyFingerprint);

        if (!TryValidateSessionKey(sessionKey))
        {
            CryptographicOperations.ZeroMemory(maskingKey);
            CryptographicOperations.ZeroMemory(sessionKey);
            replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic("Failed to process session key securely")));
            return;
        }

        byte[] maskingKeyCopy = (byte[])maskingKey.Clone();
        byte[] sessionKeyCopy = (byte[])sessionKey.Clone();
        CryptographicOperations.ZeroMemory(sessionKey);

        Result<Option<Guid>, VerificationFlowFailure> accountResult =
            await _persistor.Ask<Result<Option<Guid>, VerificationFlowFailure>>(
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

        Serilog.Log.Information(
            "[PASSWORD-RECOVERY-INIT] OPRF generated for membership {MembershipId}. Credentials stored in pending state (persisted).",
            @event.MembershipIdentifier);

        PersistAsync(
            new RecoverySessionStartedEvent(
                @event.MembershipIdentifier,
                maskingKeyCopy,
                sessionKeyCopy,
                DateTime.UtcNow),
            evt =>
            {
                Apply(evt);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OprfRecoverySecureKeyInitResponse, VerificationFlowFailure>.Ok(response));
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

        PersistAsync(
            new RegistrationMaskingKeyStoredEvent(@event.MembershipIdentifier, maskingKey),
            evt =>
            {
                Apply(evt);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OprfRegistrationInitResponse, VerificationFlowFailure>.Ok(response));
            });

        await Task.CompletedTask;
    }

    private async Task HandleCreateMembership(CreateMembershipActorEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event,
                @event.CancellationToken);
        Sender.Tell(operationResult);
    }

    private async Task HandleGetMembershipByVerificationFlow(GetMembershipByVerificationFlowEvent @event)
    {
        Result<MembershipQueryRecord, VerificationFlowFailure> operationResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event,
                @event.CancellationToken);
        Sender.Tell(operationResult);
    }

    private async Task HandleSignInMembership(SignInMembershipActorEvent @event)
    {
        IActorRef replyTo = Sender;

        Result<MembershipQueryRecord, VerificationFlowFailure> persistorResult =
            await _persistor.Ask<Result<MembershipQueryRecord, VerificationFlowFailure>>(@event,
                @event.CancellationToken);

        if (persistorResult.IsErr)
        {
            replyTo.Tell(TranslateSignInFailure(persistorResult.UnwrapErr(), @event.CultureName));
            return;
        }

        MembershipQueryRecord record = persistorResult.Unwrap();

        Result<(OpaqueSignInInitResponse Response, byte[] ServerMac), OpaqueFailure> initiateSignInResult =
            _opaqueProtocolService.InitiateSignIn(
                @event.OpaqueSignInInitRequest,
                new MembershipOpaqueQueryRecord(@event.MobileNumber, record.SecureKey, record.MaskingKey));

        if (initiateSignInResult.IsErr)
        {
            replyTo.Tell(Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque()));
            return;
        }

        (OpaqueSignInInitResponse response, byte[] serverMac) = initiateSignInResult.Unwrap();

        List<AccountInfo>? accountsCopy = record.AvailableAccounts?.Select(CloneAccountInfo).ToList();

        PersistAsync(
            new PendingSignInStoredEvent(
                @event.ConnectId,
                record.UniqueIdentifier,
                Guid.NewGuid(),
                @event.MobileNumber,
                record.ActivityStatus,
                record.CreationStatus,
                DateTime.UtcNow,
                serverMac,
                accountsCopy,
                record.ActiveAccountId),
            evt =>
            {
                Apply(evt);
                MaybeSaveSnapshot();
                replyTo.Tell(Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(response));
            });
    }

    private async Task HandleSignInComplete(SignInCompleteEvent @event)
    {
        IActorRef replyTo = Sender;

        if (!_pendingSignIns.TryGetValue(@event.ConnectId, out PendingSignInState? state))
        {
            replyTo.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque("No matching sign-in initiation found for this connection")));
            return;
        }

        Result<(SodiumSecureMemoryHandle SessionKeyHandle, OpaqueSignInFinalizeResponse Response), OpaqueFailure>
            opaqueResult =
                _opaqueProtocolService.CompleteSignIn(@event.Request, state.ServerMac);

        if (opaqueResult.IsErr)
        {
            RemovePendingSignIn(@event.ConnectId);
            replyTo.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Err(
                VerificationFlowFailure.InvalidOpaque(opaqueResult.UnwrapErr().Message)));
            return;
        }

        (SodiumSecureMemoryHandle sessionKeyHandle, OpaqueSignInFinalizeResponse finalizeResponse) =
            opaqueResult.Unwrap();

        // SessionKeyHandle is null when OPAQUE authentication fails (wrong password)
        if (sessionKeyHandle != null)
        {
            Result<byte[], SodiumFailure> sessionKeyBytesResult = sessionKeyHandle.ReadBytes(sessionKeyHandle.Length);
            if (sessionKeyBytesResult.IsOk)
            {
                byte[] sessionKeyBytes = sessionKeyBytesResult.Unwrap();
                string sessionKeyFingerprint = Convert.ToHexString(SHA256.HashData(sessionKeyBytes))[..16];
                Serilog.Log.Information(
                    "[SERVER-OPAQUE-EXPORTKEY] OPAQUE export_key (session key) derived. MembershipId: {MembershipId}, SessionKeyFingerprint: {SessionKeyFingerprint}",
                    state.MembershipId, sessionKeyFingerprint);
                CryptographicOperations.ZeroMemory(sessionKeyBytes);
            }

            if (finalizeResponse.Result == OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded &&
                !sessionKeyHandle.IsInvalid)
            {
                await EnsureMasterKeySharesExist(sessionKeyHandle, state.MembershipId);
            }
        }
        else
        {
            Serilog.Log.Information(
                "[SERVER-OPAQUE-AUTH-FAILED] OPAQUE authentication failed (session key is null). ConnectId: {ConnectId}, MembershipId: {MembershipId}, Result: {Result}",
                @event.ConnectId, state.MembershipId, finalizeResponse.Result);
        }

        RemovePendingSignIn(@event.ConnectId);

        finalizeResponse.Membership = new Membership
        {
            UniqueIdentifier = Helpers.GuidToByteString(state.MembershipId),
            Status = state.ActivityStatus,
            CreationStatus = state.CreationStatus,
            AccountUniqueIdentifier = state.ActiveAccountId.HasValue
                ? Helpers.GuidToByteString(state.ActiveAccountId.Value)
                : null
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

        replyTo.Tell(Result<OpaqueSignInFinalizeResponse, VerificationFlowFailure>.Ok(finalizeResponse));
    }

    private Task HandleCleanupExpiredPendingSignIns()
    {
        DateTime cutoffTime = DateTime.UtcNow - PendingSignInTimeout;
        List<uint> expiredConnections = _pendingSignIns
            .Where(kvp => kvp.Value.CreatedAt < cutoffTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (uint connectId in expiredConnections)
        {
            RemovePendingSignIn(connectId);
        }

        return Task.CompletedTask;
    }

    private Task HandleCleanupExpiredPasswordRecovery()
    {
        DateTime cutoffTime = DateTime.UtcNow - PendingPasswordRecoveryTimeout;
        List<Guid> expiredRecoveries = _pendingRecoveryTimestamps
            .Where(kvp => kvp.Value < cutoffTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (Guid membershipId in expiredRecoveries)
        {
            Serilog.Log.Information("Cleaning up expired password recovery attempt for membership {MembershipId}",
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
        if (LastSequenceNr == 0 || LastSequenceNr % SnapshotInterval != 0)
        {
            return;
        }

        SaveSnapshot(CreateSnapshot());
    }

    private MembershipActorSnapshot CreateSnapshot()
    {
        List<PendingSignInStoredEvent> pendingSignIns = _pendingSignIns
            .Select(kvp => new PendingSignInStoredEvent(
                kvp.Key,
                kvp.Value.MembershipId,
                kvp.Value.MobileNumberId,
                kvp.Value.MobileNumber,
                kvp.Value.ActivityStatus,
                kvp.Value.CreationStatus,
                kvp.Value.CreatedAt,
                (byte[])kvp.Value.ServerMac.Clone(),
                kvp.Value.AvailableAccounts?.Select(CloneAccountInfo).ToList(),
                kvp.Value.ActiveAccountId))
            .ToList();

        List<RegistrationMaskingKeyStoredEvent> pendingMaskingKeys = _pendingMaskingKeys
            .Select(kvp => new RegistrationMaskingKeyStoredEvent(
                kvp.Key,
                (byte[])kvp.Value.Clone()))
            .ToList();

        List<RecoverySessionSnapshot> recoverySessions = new();
        foreach ((Guid membershipId, DateTime startedAt) in _pendingRecoveryTimestamps)
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
            Log.Error("Failed to allocate secure memory for session key: {Error}", allocateResult.UnwrapErr().Message);
            return;
        }

        SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
        Result<Unit, SodiumFailure> writeResult = handle.Write(sessionKeyBytes);

        if (writeResult.IsErr)
        {
            Log.Error("Failed to write session key to secure memory: {Error}", writeResult.UnwrapErr().Message);
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
            Serilog.Log.Error("Failed to allocate secure memory for session key validation: {Error}",
                allocateResult.UnwrapErr().Message);
            return false;
        }

        using SodiumSecureMemoryHandle handle = allocateResult.Unwrap();
        Result<Unit, SodiumFailure> writeResult = handle.Write(sessionKey);

        if (writeResult.IsErr)
        {
            Serilog.Log.Error("Failed to write session key to secure memory during validation: {Error}",
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
            Serilog.Log.Error("Failed to read session key bytes for snapshot: {Error}", readResult.UnwrapErr().Message);
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
        Result<bool, FailureBase> checkResult = await _masterKeyService.CheckSharesExistAsync(membershipId);

        if (checkResult.IsErr || !checkResult.Unwrap())
        {
            Result<dynamic, FailureBase> createResult =
                await _masterKeyService.DeriveMasterKeyAndSplitAsync(sessionKeyHandle, membershipId);

            if (createResult.IsErr)
            {
                Log.Error(
                    "[MASTER-KEY-CREATE] Failed to create master key shares for membership {MembershipId}: {Error}",
                    membershipId,
                    createResult.UnwrapErr().Message);
            }
            else
            {
                Serilog.Log.Information(
                    "[MASTER-KEY-CREATE] Successfully created master key shares for membership {MembershipId} on first login",
                    membershipId);
            }

            return;
        }

        Result<string, FailureBase> validationResult =
            await _masterKeyService.ValidateMasterKeySharesAsync(sessionKeyHandle, membershipId);

        if (validationResult.IsErr)
        {
            Log.Error(
                "[MASTER-KEY-VALIDATE] Failed to validate master key shares for membership {MembershipId}: {Error}",
                membershipId, validationResult.UnwrapErr().Message);
            return;
        }

        string validationStatus = validationResult.Unwrap();

        if (validationStatus == "mismatch")
        {
            Serilog.Log.Warning(
                "[MASTER-KEY-MISMATCH] Export key mismatch detected for membership {MembershipId}. OPAQUE credentials changed since last login. Regenerating master key shares...",
                membershipId);

            Result<dynamic, FailureBase> regenResult =
                await _masterKeyService.RegenerateMasterKeySharesAsync(sessionKeyHandle, membershipId);

            if (regenResult.IsErr)
            {
                Log.Error(
                    "[MASTER-KEY-REGEN] CRITICAL: Failed to regenerate master key shares for membership {MembershipId}: {Error}",
                    membershipId,
                    regenResult.UnwrapErr().Message);
            }
            else
            {
                Serilog.Log.Information(
                    "[MASTER-KEY-REGEN] Successfully regenerated master key shares for membership {MembershipId} after export key change",
                    membershipId);
            }
        }
        else
        {
            Serilog.Log.Information(
                "[MASTER-KEY-VALID] Master key shares are valid for membership {MembershipId}. No regeneration needed.",
                membershipId);
        }
    }

    private Result<OpaqueSignInInitResponse, VerificationFlowFailure> TranslateSignInFailure(
        VerificationFlowFailure failure,
        string cultureName)
    {
        switch (failure.FailureType)
        {
            case VerificationFlowFailureType.Validation:
            case VerificationFlowFailureType.NotFound:
            {
                string message = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.InvalidCredentials,
                    cultureName
                );
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.InvalidCredentials, Message = message
                });
            }

            case VerificationFlowFailureType.RateLimitExceeded:
            {
                string messageTemplate = _localizationProvider.Localize(
                    VerificationFlowMessageKeys.TooManySigninAttempts,
                    cultureName
                );

                int.TryParse(failure.Message, out int minutesUntilRetry);
                string message = string.Format(messageTemplate, minutesUntilRetry);

                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>.Ok(new OpaqueSignInInitResponse
                {
                    Result = OpaqueSignInInitResponse.Types.SignInResult.LoginAttemptExceeded,
                    Message = message,
                    MinutesUntilRetry = minutesUntilRetry
                });
            }

            default:
                return Result<OpaqueSignInInitResponse, VerificationFlowFailure>
                    .Err(failure);
        }
    }
}

public record UpdateMembershipSecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] SecureKey,
    byte[] MaskingKey,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record GenerateMembershipOprfRegistrationRequestEvent(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record CompleteRegistrationRecordActorEvent(
    Guid MembershipIdentifier,
    byte[] PeerRegistrationRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record OprfInitRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] OprfRequest,
    string CultureName,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record OprfCompleteRecoverySecureKeyEvent(
    Guid MembershipIdentifier,
    byte[] PeerRecoveryRecord,
    CancellationToken CancellationToken = default) : ICancellableActorEvent;

public record SignInCompleteEvent(uint ConnectId, OpaqueSignInFinalizeRequest Request);

internal record CleanupExpiredPendingSignIns;

internal record CleanupExpiredPasswordRecovery;
