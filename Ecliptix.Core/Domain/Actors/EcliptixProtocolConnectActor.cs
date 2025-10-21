using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Domain.Protocol.Handlers;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;
using Unit = Ecliptix.Utilities.Unit;

namespace Ecliptix.Core.Domain.Actors;

public sealed class EcliptixProtocolConnectActor(uint connectId) : PersistentActor, IWithTimers
{
    public ITimerScheduler Timers { get; set; } = null!;

    public override string PersistenceId { get; } = $"{ActorConstants.ActorNamePrefixes.Connect}{connectId}";

    private const int SnapshotInterval = ActorConstants.Constants.SnapshotInterval;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(ActorConstants.Timeouts.IdleTimeoutMinutes);
    private const int MaxRecoveryRetries = ActorConstants.Recovery.MaxRetries;
    private const string RecoveryRetryTimerKey = ActorConstants.Recovery.RetryTimerKey;

    private EcliptixSessionState? _state;
    private readonly Dictionary<PubKeyExchangeType, EcliptixProtocolSystem> _protocolSystems = new();
    private int _recoveryRetryCount;
    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion;
    private bool _pendingSnapshotDeletion;
    private PubKeyExchangeType? _currentExchangeType;
    private readonly EncryptionHandler _encryptionHandler = new();
    private readonly DecryptionHandler _decryptionHandler = new();
    private readonly StateValidationHandler _stateValidationHandler = new();

    protected override bool ReceiveRecover(object message)
    {
        switch (message)
        {
            case SnapshotOffer { Snapshot: EcliptixSessionState state }:
                _state = state;
                return true;
            case EcliptixSessionState state:
                _state = state;
                return true;
            case RecoveryCompleted:
                Context.GetLogger().Info(ActorConstants.LogMessages.RecoveryCompleted, Self.Path.Name);
                if (_state != null)
                {
                    AttemptSystemRecreation();
                }
                else
                {
                    Context.GetLogger()
                        .Info(ActorConstants.LogMessages.NoSessionState, connectId);
                }

                return true;
            default:
                return false;
        }
    }

    protected override bool ReceiveCommand(object message)
    {
        switch (message)
        {
            case InitializeProtocolWithMasterKeyActorEvent cmd:
                HandleAuthenticatedProtocolInitialization(cmd);
                return true;
            case DeriveSharedSecretActorEvent cmd:
                HandleInitialKeyExchange(cmd);
                return true;
            case EncryptPayloadActorEvent cmd:
                HandleEncrypt(cmd);
                return true;
            case DecryptSecureEnvelopeActorEvent cmd:
                HandleDecrypt(cmd);
                return true;
            case EncryptPayloadComponentsActorEvent cmd:
                HandleEncryptComponents(cmd);
                return true;
            case DecryptPayloadWithHeaderActorEvent cmd:
                HandleDecryptWithHeader(cmd);
                return true;
            case CleanupProtocolForTypeActorEvent cmd:
                HandleCleanupProtocolForType(cmd);
                return true;
            case ProtocolCleanupRequiredEvent evt:
                HandleProtocolCleanupRequired(evt);
                return true;
            case RestoreAppDeviceSecrecyChannelState:
                HandleRestoreSecrecyChannelState();
                return true;
            case GetProtocolStateActorEvent:
                HandleGetProtocolState();
                return true;
            case KeepAlive:
                return true;
            case RetryRecoveryMessage:
                AttemptSystemRecreation();
                return true;

            case ReceiveTimeout:
                SaveFinalSnapshot();
                return true;

            case SaveSnapshotSuccess success:
                if (_savingFinalSnapshot)
                {
                    Context.GetLogger().Info(ActorConstants.LogMessages.FinalSnapshotSaved);
                    _pendingMessageDeletion = true;
                    _pendingSnapshotDeletion = true;
                }

                DeleteMessages(success.Metadata.SequenceNr);
                DeleteSnapshots(new SnapshotSelectionCriteria(success.Metadata.SequenceNr - 1));

                return true;
            case SaveSnapshotFailure:
                return true;

            case DeleteMessagesSuccess:
                if (!_savingFinalSnapshot || !_pendingMessageDeletion)
                {
                    return true;
                }

                _pendingMessageDeletion = false;
                TryCompleteShutdown();

                return true;
            case DeleteSnapshotsSuccess:
                if (!_savingFinalSnapshot || !_pendingSnapshotDeletion)
                {
                    return true;
                }

                _pendingSnapshotDeletion = false;
                TryCompleteShutdown();

                return true;

            case DeleteMessagesFailure failure:
                Context.GetLogger().Warning("[PERSISTENCE-DELETE-MSG-FAILED] Failed to delete messages. " +
                                            "PersistenceId: {0}, Error: {1}. This is non-critical - continuing operation.",
                    PersistenceId, failure.Cause?.Message ?? "Unknown");
                if (!_savingFinalSnapshot || !_pendingMessageDeletion)
                {
                    return true;
                }

                _pendingMessageDeletion = false;
                TryCompleteShutdown();

                return true;

            case DeleteSnapshotsFailure failure:
                Context.GetLogger().Warning("[PERSISTENCE-DELETE-SNAP-FAILED] Failed to delete snapshots. " +
                                            "PersistenceId: {0}, Error: {1}. This is non-critical - continuing operation.",
                    PersistenceId, failure.Cause?.Message ?? "Unknown");

                if (!_savingFinalSnapshot || !_pendingSnapshotDeletion)
                {
                    return true;
                }

                _pendingSnapshotDeletion = false;
                TryCompleteShutdown();
                return true;

            default:
                return false;
        }
    }

    protected override void PreStart()
    {
        base.PreStart();
        Context.GetLogger()
            .Info("[PROTOCOL_ACTOR] Starting and subscribing to ProtocolCleanupRequiredEvent - ConnectId: {0}",
                connectId);
        Context.System.EventStream.Subscribe(Self, typeof(ProtocolCleanupRequiredEvent));
    }

    protected override void PostStop()
    {
        Timers.CancelAll();
        DisposeAllSystems();
        base.PostStop();
    }

    private void HandleRestoreSecrecyChannelState()
    {
        if (_currentExchangeType == PubKeyExchangeType.ServerStreaming)
        {
            Context.GetLogger().Info(ActorConstants.LogMessages.SessionRestorationPrevented);

            RestoreSecrecyChannelResponse streamingReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = ActorConstants.Constants.Zero,
                SendingChainLength = ActorConstants.Constants.Zero
            };

            Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(streamingReply));
            return;
        }

        Option<EcliptixProtocolSystem> defaultSystemOpt = GetDefaultProtocolSystem();
        if (!defaultSystemOpt.HasValue || _state == null)
        {
            RestoreSecrecyChannelResponse notFoundReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = ActorConstants.Constants.Zero,
                SendingChainLength = ActorConstants.Constants.Zero
            };

            Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(notFoundReply));
            return;
        }

        EcliptixProtocolSystem defaultSystem = defaultSystemOpt.Value!;

        Result<Unit, EcliptixProtocolFailure> stateValidation = _stateValidationHandler.ValidateRecoveredState(_state);
        if (stateValidation.IsErr)
        {
            Context.GetLogger().Warning(ActorConstants.LogMessages.StateIntegrityValidationFailed,
                stateValidation.UnwrapErr().Message);

            RestoreSecrecyChannelResponse failureReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = ActorConstants.Constants.Zero,
                SendingChainLength = ActorConstants.Constants.Zero
            };

            Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(failureReply));

            DisposeAllSystems();
            _state = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        try
        {
            defaultSystem.GetConnection();
        }
        catch (InvalidOperationException)
        {
            Context.GetLogger()
                .Warning("[SERVER-RESTORE] Fresh handshake required. ConnectId: {0}, Reason: InvalidConnection",
                    connectId);

            RestoreSecrecyChannelResponse freshHandshakeReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = ActorConstants.Constants.Zero,
                SendingChainLength = ActorConstants.Constants.Zero
            };

            Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(freshHandshakeReply));

            DisposeAllSystems();
            _state = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        DateTime lastPersistTime = GetLastPersistenceTime();

        RestoreSecrecyChannelResponse reply = new()
        {
            ReceivingChainLength = _state.RatchetState.ReceivingStep.CurrentIndex,
            SendingChainLength = _state.RatchetState.SendingStep.CurrentIndex,
            Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionResumed
        };

        Context.GetLogger().Info(
            "[SERVER-RESTORE] Returning session state. ConnectId: {0}, ServerSending: {1}, ServerReceiving: {2}, LastPersist: {3}, Status: SessionResumed",
            connectId, reply.SendingChainLength, reply.ReceivingChainLength, lastPersistTime);

        Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(reply));
    }

    private void HandleGetProtocolState()
    {
        Context.GetLogger().Debug("[GET-PROTOCOL-STATE] Retrieving session state for ConnectId: {ConnectId}",
            connectId);

        if (_state == null)
        {
            Context.GetLogger().Info("[GET-PROTOCOL-STATE] No session state found for ConnectId: {ConnectId}",
                connectId);
            Sender.Tell(new GetProtocolStateReply(null));
            return;
        }

        GetProtocolStateReply reply = new(_state);
        Sender.Tell(reply);

        Context.GetLogger().Debug("[GET-PROTOCOL-STATE] Session state retrieved for ConnectId: {ConnectId}", connectId);
    }

    private DateTime GetLastPersistenceTime()
    {
        return DateTime.UtcNow.AddMinutes(-((SnapshotSequenceNr % ActorConstants.Constants.SnapshotModulus) *
                                            ActorConstants.Constants.SnapshotMinuteMultiplier));
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
        PubKeyExchangeType exchangeType = cmd.PubKeyExchange.OfType;
        if (_protocolSystems.TryGetValue(exchangeType, out EcliptixProtocolSystem? existingSystem) && _state != null)
        {
            Context.GetLogger()
                .Info(ActorConstants.LogMessages.UsingExistingSession, cmd.ConnectId, exchangeType);
            Result<PubKeyExchange, EcliptixProtocolFailure> existingReplyResult =
                existingSystem.ProcessAndRespondToPubKeyExchange(cmd.ConnectId, cmd.PubKeyExchange);

            bool sessionStillValid = true;
            try
            {
                existingSystem.GetConnection();
            }
            catch (InvalidOperationException)
            {
                Context.GetLogger()
                    .Info(ActorConstants.LogMessages.SystemDetectedFreshHandshake);
                DisposeAllSystems();
                _state = null;
                sessionStillValid = false;
                SaveSnapshot(new EcliptixSessionState());
            }

            if (sessionStillValid)
            {
                if (existingReplyResult.IsOk)
                {
                    Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
                        EcliptixProtocol.CreateStateFromSystem(_state!, existingSystem!);
                    if (newStateResult.IsOk)
                    {
                        _state = newStateResult.Unwrap();
                        Persist(_state, _ => { });
                    }

                    _currentExchangeType = exchangeType;
                    if (exchangeType == PubKeyExchangeType.ServerStreaming)
                    {
                        Context.SetReceiveTimeout(null);
                        Context.GetLogger()
                            .Info(
                                "[PROTOCOL] ServerStreaming - no timeout, controlled by VerificationFlow for ConnectId {0}",
                                cmd.ConnectId);
                    }
                    else
                    {
                        Context.SetReceiveTimeout(IdleTimeout);
                        Context.GetLogger().Info("[PROTOCOL] {0} - using idle timeout for ConnectId {1}", exchangeType,
                            cmd.ConnectId);
                    }

                    if (existingReplyResult.IsOk)
                    {
                        PubKeyExchange pubKeyReply = existingReplyResult.Unwrap();
                        Sender.Tell(
                            Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(
                                new DeriveSharedSecretReply(pubKeyReply)));
                    }
                    else
                    {
                        Sender.Tell(
                            Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(
                                existingReplyResult.UnwrapErr()));
                    }
                }
                else
                {
                    Sender.Tell(
                        Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(existingReplyResult.UnwrapErr()));
                }

                return;
            }
        }

        Context.GetLogger().Info(ActorConstants.LogMessages.CreatingNewSession, cmd.ConnectId, exchangeType);

        EcliptixSystemIdentityKeys identityKeys =
            EcliptixSystemIdentityKeys.Create(ActorConstants.Constants.IdentityKeySize).Unwrap();

        EcliptixProtocolSystem system = new(identityKeys);

        Context.GetLogger().Info("[PROTOCOL] Created protocol system for exchange type {0}", exchangeType);
        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAndRespondToPubKeyExchange(cmd.ConnectId, cmd.PubKeyExchange);

        if (replyResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(replyResult.UnwrapErr()));
            system.Dispose();
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            EcliptixProtocol.CreateInitialState(cmd.ConnectId, cmd.PubKeyExchange, system);
        if (stateToPersistResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(stateToPersistResult.UnwrapErr()));
            system.Dispose();
            return;
        }

        EcliptixSessionState newState = stateToPersistResult.Unwrap();
        PubKeyExchange reply = replyResult.Unwrap();
        IActorRef? originalSender = Sender;

        Persist(newState, state =>
        {
            _state = state;
            _protocolSystems[exchangeType] = system;
            _currentExchangeType = exchangeType;

            if (exchangeType != PubKeyExchangeType.DataCenterEphemeralConnect)
            {
                Context.SetReceiveTimeout(null);
            }
            else
            {
                Context.SetReceiveTimeout(IdleTimeout);
            }

            originalSender.Tell(
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleAuthenticatedProtocolInitialization(InitializeProtocolWithMasterKeyActorEvent cmd)
    {
        PubKeyExchangeType exchangeType = cmd.ClientPubKeyExchange.OfType;

        if (_protocolSystems.TryGetValue(exchangeType, out EcliptixProtocolSystem? existingSystem) && _state != null)
        {
            EcliptixSystemIdentityKeys existingKeys = existingSystem.GetIdentityKeys();
            bool keysMatch = AreIdentityKeysEqual(existingKeys, cmd.IdentityKeys);

            if (keysMatch)
            {
                string reuseRootKeyHash =
                    Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cmd.RootKey))[..16];

                Context.GetLogger().Info(
                    "[SERVER-AUTH-REUSE] Reusing existing authenticated session. ConnectId: {0}, MembershipId: {1}, Sending: {2}, Receiving: {3}, ExchangeType: {4}, RootKeyHash: {5}",
                    cmd.ConnectId, cmd.MembershipId, _state?.RatchetState?.SendingStep?.CurrentIndex,
                    _state?.RatchetState?.ReceivingStep?.CurrentIndex, exchangeType, reuseRootKeyHash);

                Result<PubKeyExchange, EcliptixProtocolFailure> existingReplyResult =
                    existingSystem.ProcessAuthenticatedPubKeyExchange(cmd.ConnectId, cmd.ClientPubKeyExchange,
                        cmd.RootKey);

                if (existingReplyResult.IsOk)
                {
                    Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
                        EcliptixProtocol.CreateStateFromSystem(_state, existingSystem);
                    if (newStateResult.IsOk)
                    {
                        _state = newStateResult.Unwrap();
                        Persist(_state, _ => { });
                    }

                    _currentExchangeType = exchangeType;

                    if (exchangeType == PubKeyExchangeType.ServerStreaming)
                    {
                        Context.SetReceiveTimeout(null);
                    }
                    else
                    {
                        Context.SetReceiveTimeout(IdleTimeout);
                    }

                    PubKeyExchange pubKeyReply = existingReplyResult.Unwrap();
                    Sender.Tell(
                        Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                            new InitializeProtocolWithMasterKeyReply(pubKeyReply)));
                }
                else
                {
                    Sender.Tell(
                        Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(existingReplyResult
                            .UnwrapErr()));
                }

                cmd.IdentityKeys.Dispose();
                return;
            }

            Context.GetLogger().Warning(
                "[PROTOCOL] Identity key mismatch detected for ConnectId {0}, ExchangeType {1} - disposing old system and creating new authenticated session",
                cmd.ConnectId, exchangeType);

            existingSystem.Dispose();
            _protocolSystems.Remove(exchangeType);
            _state = null;
            _currentExchangeType = null;

            Context.GetLogger().Info(
                "[PROTOCOL-CLEANUP] Saving empty snapshot after anonymous session disposal. ConnectId: {0}",
                cmd.ConnectId);
            SaveSnapshot(new EcliptixSessionState());
        }

        Context.GetLogger().Info(
            "[SERVER-AUTH-NEW] Creating new authenticated session. ConnectId: {0}, MembershipId: {1}, ExchangeType: {2}",
            cmd.ConnectId, cmd.MembershipId, exchangeType);

        string rootKeyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cmd.RootKey))[..16];
        Context.GetLogger().Info(
            "[SERVER-AUTH-ROOTKEY] Received root key for authenticated session. ConnectId: {0}, MembershipId: {1}, RootKeyHash: {2}",
            cmd.ConnectId, cmd.MembershipId, rootKeyHash);

        EcliptixProtocolSystem system = new(cmd.IdentityKeys);

        Context.GetLogger().Info("[PROTOCOL] Processing authenticated pub key exchange for ConnectId {0}",
            cmd.ConnectId);
        Result<PubKeyExchange, EcliptixProtocolFailure> replyResult =
            system.ProcessAuthenticatedPubKeyExchange(cmd.ConnectId, cmd.ClientPubKeyExchange, cmd.RootKey);

        if (replyResult.IsErr)
        {
            Sender.Tell(
                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(replyResult.UnwrapErr()));
            system.Dispose();
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> stateToPersistResult =
            EcliptixProtocol.CreateInitialState(cmd.ConnectId, cmd.ClientPubKeyExchange, system);
        if (stateToPersistResult.IsErr)
        {
            Sender.Tell(
                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Err(
                    stateToPersistResult.UnwrapErr()));
            system.Dispose();
            return;
        }

        EcliptixSessionState newState = stateToPersistResult.Unwrap();
        newState.MembershipId = Helpers.GuidToByteString(cmd.MembershipId);

        PubKeyExchange reply = replyResult.Unwrap();
        IActorRef? originalSender = Sender;

        Persist(newState, state =>
        {
            _state = state;
            _protocolSystems[exchangeType] = system;
            _currentExchangeType = exchangeType;

            if (exchangeType == PubKeyExchangeType.ServerStreaming)
            {
                Context.SetReceiveTimeout(null);
                Context.GetLogger()
                    .Info("[PROTOCOL] AuthenticatedSession ServerStreaming - no timeout for ConnectId {0}",
                        cmd.ConnectId);
            }
            else
            {
                Context.SetReceiveTimeout(IdleTimeout);
                Context.GetLogger().Info("[PROTOCOL] AuthenticatedSession {0} - using idle timeout for ConnectId {1}",
                    exchangeType, cmd.ConnectId);
            }

            string persistedRootKeyHash =
                Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(state.RatchetState.RootKey.ToByteArray()))[..16];
            string sendingChainKeyHash =
                Convert.ToHexString(
                        System.Security.Cryptography.SHA256.HashData(
                            state.RatchetState.SendingStep.ChainKey.ToByteArray()))
                    [..16];
            string receivingChainKeyHash =
                Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        state.RatchetState.ReceivingStep.ChainKey.ToByteArray()))[..16];

            Context.GetLogger().Info(
                "[SERVER-AUTH-PROTOCOL-STATE] Authenticated protocol state created. ConnectId: {0}, RootKeyHash: {1}, SendingChainKeyHash: {2}, ReceivingChainKeyHash: {3}",
                cmd.ConnectId, persistedRootKeyHash, sendingChainKeyHash, receivingChainKeyHash);

            Context.GetLogger().Info(
                "[SERVER-AUTH-PERSISTED] Authenticated session persisted. ConnectId: {0}, MembershipId: {1}, Sending: {2}, Receiving: {3}",
                cmd.ConnectId, cmd.MembershipId, state.RatchetState.SendingStep.CurrentIndex,
                state.RatchetState.ReceivingStep.CurrentIndex);

            SaveSnapshot(_state);
            Context.GetLogger().Info(
                "[SNAPSHOT-FORCE] Forced snapshot save after authenticated handshake. ConnectId: {0}, SeqNr: {1}",
                cmd.ConnectId, LastSequenceNr);

            originalSender.Tell(
                Result<InitializeProtocolWithMasterKeyReply, EcliptixProtocolFailure>.Ok(
                    new InitializeProtocolWithMasterKeyReply(reply)));
        });
    }

    private bool AreIdentityKeysEqual(EcliptixSystemIdentityKeys keys1, EcliptixSystemIdentityKeys keys2)
    {
        try
        {
            byte[] publicKey1 = keys1.IdentityX25519PublicKey;
            byte[] publicKey2 = keys2.IdentityX25519PublicKey;

            return publicKey1.SequenceEqual(publicKey2);
        }
        catch (Exception ex)
        {
            Context.GetLogger().Warning(
                "[PROTOCOL] Failed to compare identity keys: {0} - treating as different keys",
                ex.Message);
            return false;
        }
    }

    private void HandleEncrypt(EncryptPayloadActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> defaultSystemOpt = GetDefaultProtocolSystem();
            if (!defaultSystemOpt.HasValue || _state == null)
            {
                Sender.Tell(
                    Result<SecureEnvelope, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.PubKeyExchangeType}")));
                return;
            }
            system = defaultSystemOpt.Value!;
        }

        Context.GetLogger().Info("[ENCRYPT] Using protocol system for type {0}", cmd.PubKeyExchangeType);

        if (_state != null)
        {
            Context.GetLogger().Info(
                "[SERVER-ENCRYPT-BEFORE] Current _state before encryption. ConnectId: {0}, Sending: {1}, Receiving: {2}",
                connectId, _state.RatchetState.SendingStep.CurrentIndex,
                _state.RatchetState.ReceivingStep.CurrentIndex);
        }
        else
        {
            Context.GetLogger().Warning("[SERVER-ENCRYPT-BEFORE] _state is NULL before encryption. ConnectId: {0}",
                connectId);
        }

        Result<EncryptionResult, EcliptixProtocolFailure> result =
            _encryptionHandler.EncryptPayload(system, _state, cmd.Payload, cmd.PubKeyExchangeType);

        if (result.IsErr)
        {
            Sender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Err(result.UnwrapErr()));
            return;
        }

        EncryptionResult encryptionResult = result.Unwrap();
        IActorRef? originalSender = Sender;

        Context.GetLogger().Info(
            "[SERVER-ENCRYPT-CHECK] ExchangeType: {0}, NewState after encryption Sending: {1}, Receiving: {2}",
            cmd.PubKeyExchangeType, encryptionResult.NewState.RatchetState.SendingStep.CurrentIndex,
            encryptionResult.NewState.RatchetState.ReceivingStep.CurrentIndex);

        if (encryptionResult.ShouldPersist)
        {
            Persist(encryptionResult.NewState, state =>
            {
                _state = state;
                Context.GetLogger().Info(
                    "[SERVER-ENCRYPT] Message encrypted and state persisted. ConnectId: {0}, Sending: {1}, Receiving: {2}",
                    connectId, state.RatchetState.SendingStep.CurrentIndex,
                    state.RatchetState.ReceivingStep.CurrentIndex);
                originalSender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(encryptionResult.Envelope));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = encryptionResult.NewState;
            originalSender.Tell(Result<SecureEnvelope, EcliptixProtocolFailure>.Ok(encryptionResult.Envelope));
        }
    }

    private void HandleDecrypt(DecryptSecureEnvelopeActorEvent actorEvent)
    {
        if (!_protocolSystems.TryGetValue(actorEvent.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> defaultSystemOpt = GetDefaultProtocolSystem();
            if (!defaultSystemOpt.HasValue || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {actorEvent.PubKeyExchangeType}")));
                return;
            }
            system = defaultSystemOpt.Value!;
        }

        Context.GetLogger().Info("[DECRYPT] Using protocol system for type {0}", actorEvent.PubKeyExchangeType);

        if (_state != null)
        {
            Context.GetLogger().Info(
                "[SERVER-DECRYPT-BEFORE] Current _state before decryption. ConnectId: {0}, Sending: {1}, Receiving: {2}",
                connectId, _state.RatchetState.SendingStep.CurrentIndex,
                _state.RatchetState.ReceivingStep.CurrentIndex);
        }

        Context.GetLogger().Info(
            "[SERVER-DECRYPT-ENVELOPE] Incoming envelope. ConnectId: {0}, HeaderNonce: {1}, AuthTag: {2}",
            connectId,
            Convert.ToHexString(actorEvent.SecureEnvelope.HeaderNonce.ToByteArray())[
                ..Math.Min(16, actorEvent.SecureEnvelope.HeaderNonce.Length * 2)],
            actorEvent.SecureEnvelope.AuthenticationTag != null
                ? Convert.ToHexString(actorEvent.SecureEnvelope.AuthenticationTag.ToByteArray())[
                    ..Math.Min(16, actorEvent.SecureEnvelope.AuthenticationTag.Length * 2)]
                : "NULL");

        Result<DecryptionResult, EcliptixProtocolFailure> result =
            _decryptionHandler.DecryptEnvelope(system, _state, actorEvent.SecureEnvelope,
                actorEvent.PubKeyExchangeType);

        if (result.IsErr)
        {
            EcliptixProtocolFailure error = result.UnwrapErr();
            Context.GetLogger().Error(
                "[SERVER-DECRYPT-ERROR] Decryption failed. ConnectId: {0}, ErrorType: {1}, Message: {2}",
                connectId, error.FailureType, error.Message);

            if (DecryptionHandler.ShouldClearSession(error))
            {
                Context.GetLogger()
                    .Warning(
                        "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
                DisposeAllSystems();
                _state = null;
                _currentExchangeType = null;

                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
            return;
        }

        DecryptionResult decryptionResult = result.Unwrap();

        if (decryptionResult.RequiresSessionClear)
        {
            Context.GetLogger()
                .Warning(
                    "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
            DisposeAllSystems();
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Session authentication failed")));
            return;
        }

        Context.GetLogger().Info("[SERVER-DECRYPT-SUCCESS] Decryption succeeded. ConnectId: {0}", connectId);

        IActorRef? originalSender = Sender;

        Context.GetLogger().Info(
            "[SERVER-DECRYPT-CHECK] ExchangeType: {0}, ShouldPersist: {1}, NewState Sending: {2}, Receiving: {3}",
            actorEvent.PubKeyExchangeType, decryptionResult.ShouldPersist,
            decryptionResult.NewState.RatchetState.SendingStep.CurrentIndex,
            decryptionResult.NewState.RatchetState.ReceivingStep.CurrentIndex);

        if (decryptionResult.ShouldPersist)
        {
            Context.GetLogger().Info("[SERVER-DECRYPT-PERSIST] Calling Persist() for ConnectId: {0}", connectId);
            Persist(decryptionResult.NewState, state =>
            {
                _state = state;
                Context.GetLogger().Info(
                    "[SERVER-DECRYPT] Message decrypted and state persisted. ConnectId: {0}, Sending: {1}, Receiving: {2}",
                    connectId, state.RatchetState.SendingStep.CurrentIndex,
                    state.RatchetState.ReceivingStep.CurrentIndex);
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            Context.GetLogger().Info(
                "[SERVER-DECRYPT-SYNC] Updating state synchronously. ConnectId: {0}, Sending: {1}, Receiving: {2}",
                connectId, decryptionResult.NewState.RatchetState.SendingStep.CurrentIndex,
                decryptionResult.NewState.RatchetState.ReceivingStep.CurrentIndex);
            _state = decryptionResult.NewState;
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
        }
    }

    private void HandleCleanupProtocolForType(CleanupProtocolForTypeActorEvent cmd)
    {
        if (_protocolSystems.TryGetValue(cmd.ExchangeType, out EcliptixProtocolSystem? system))
        {
            Context.GetLogger().Info("[CLEANUP] Disposing protocol system for type {0}", cmd.ExchangeType);
            system?.Dispose();
            _protocolSystems.Remove(cmd.ExchangeType);

            Sender.Tell(Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value));
        }
        else
        {
            Context.GetLogger().Info("[CLEANUP] No protocol system found for type {0}", cmd.ExchangeType);
            Sender.Tell(Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value));
        }
    }

    private void HandleProtocolCleanupRequired(ProtocolCleanupRequiredEvent evt)
    {
        Context.GetLogger()
            .Info("[PROTOCOL_CLEANUP] Received ProtocolCleanupRequiredEvent - EventConnectId: {0}, ActorConnectId: {1}",
                evt.ConnectId, connectId);

        if (evt.ConnectId != connectId)
        {
            Context.GetLogger()
                .Info("[PROTOCOL_CLEANUP] ConnectId mismatch - ignoring event for ConnectId {0}", evt.ConnectId);
            return;
        }

        Context.GetLogger()
            .Info("[SESSION_CLEANUP] Clearing ALL protocol systems and state for ConnectId: {0}", connectId);

        DisposeAllSystems();
        _currentExchangeType = null;

        _state = null;

        _savingFinalSnapshot = true;
        _pendingMessageDeletion = true;
        _pendingSnapshotDeletion = true;

        SaveSnapshot(new EcliptixSessionState());

        Context.GetLogger()
            .Info("[SESSION_CLEANUP] Initiated state cleanup - will delete messages/snapshots for ConnectId: {0}",
                connectId);
    }

    private void MaybeSaveSnapshot()
    {
        if (_currentExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect && _state != null)
        {
            SaveSnapshot(_state);
            Context.GetLogger().Debug(
                "[SNAPSHOT-SAVE] Snapshot saved. ConnectId: {0}, SeqNr: {1}, Sending: {2}, Receiving: {3}",
                connectId, LastSequenceNr,
                _state.RatchetState?.SendingStep?.CurrentIndex ?? 0,
                _state.RatchetState?.ReceivingStep?.CurrentIndex ?? 0);
        }
    }

    private void SaveFinalSnapshot()
    {
        if (_state != null && !_savingFinalSnapshot)
        {
            _savingFinalSnapshot = true;
            Context.GetLogger().Info("Saving final snapshot before stopping");
            SaveSnapshot(_state);
        }
        else
        {
            Context.Stop(Self);
        }
    }

    private void TryCompleteShutdown()
    {
        if (!_pendingMessageDeletion && !_pendingSnapshotDeletion)
        {
            Context.GetLogger().Info("All cleanup operations completed. Stopping actor.");
            Context.Stop(Self);
        }
    }

    private void DisposeAllSystems()
    {
        foreach (EcliptixProtocolSystem system in _protocolSystems.Values)
        {
            system?.Dispose();
        }

        _protocolSystems.Clear();
    }

    private void AttemptSystemRecreation()
    {
        if (_state == null)
        {
            Context.GetLogger()
                .Warning($"[Recovery] No state available for system recreation for connectId {connectId}");
            return;
        }

        if (_state.PeerHandshakeMessage == null)
        {
            Context.GetLogger()
                .Warning(
                    $"[Recovery] State exists but PeerHandshakeMessage is null - clearing state for connectId {connectId}");
            _state = null;
            _currentExchangeType = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        PubKeyExchangeType exchangeType = _state.PeerHandshakeMessage.OfType;

        if (exchangeType == PubKeyExchangeType.ServerStreaming)
        {
            Context.GetLogger()
                .Info(
                    $"[Recovery] Clearing SERVER_STREAMING state - fresh handshake required for connectId {connectId}");
            _state = null;
            _currentExchangeType = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        if (Serilog.Log.IsEnabled(Serilog.Events.LogEventLevel.Debug))
        {
            int attempt = _recoveryRetryCount + 1;
            Context.GetLogger()
                .Debug(
                    "[Recovery] Attempting system recreation (attempt {0}/{1}) for connectId {2}",
                    attempt,
                    MaxRecoveryRetries,
                    connectId);
        }

        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult =
            EcliptixProtocol.RecreateSystemFromState(_state);

        if (systemResult.IsOk)
        {
            EcliptixProtocolSystem system = systemResult.Unwrap();
            _protocolSystems[exchangeType] = system;
            _recoveryRetryCount = 0;

            Context.GetLogger()
                .Info($"[Recovery] Protocol system successfully recreated for connectId {connectId}");
        }
        else
        {
            _recoveryRetryCount++;
            EcliptixProtocolFailure failure = systemResult.UnwrapErr();

            Context.GetLogger()
                .Warning(
                    $"[Recovery] Failed to recreate protocol system for connectId {connectId} (attempt {_recoveryRetryCount}/{MaxRecoveryRetries}): {failure.Message}");

            if (_recoveryRetryCount < MaxRecoveryRetries)
            {
                int delaySeconds = (int)Math.Pow(2, _recoveryRetryCount - 1) * 5;
                Context.GetLogger()
                    .Info($"[Recovery] Scheduling retry in {delaySeconds} seconds for connectId {connectId}");

                Timers.StartSingleTimer(
                    RecoveryRetryTimerKey,
                    new RetryRecoveryMessage(),
                    TimeSpan.FromSeconds(delaySeconds));
            }
            else
            {
                Context.GetLogger()
                    .Error(
                        $"[Recovery] Max recovery retries exceeded for connectId {connectId}. Continuing with degraded functionality.");

                DisposeAllSystems();

                SaveSnapshot(_state);
            }
        }
    }

    private Option<EcliptixProtocolSystem> GetDefaultProtocolSystem()
    {
        if (_protocolSystems.TryGetValue(PubKeyExchangeType.DataCenterEphemeralConnect,
                out EcliptixProtocolSystem? defaultSystem))
        {
            return Option<EcliptixProtocolSystem>.Some(defaultSystem);
        }

        EcliptixProtocolSystem? firstSystem = _protocolSystems.Values.FirstOrDefault();
        return firstSystem is not null
            ? Option<EcliptixProtocolSystem>.Some(firstSystem)
            : Option<EcliptixProtocolSystem>.None;
    }

    private void HandleEncryptComponents(EncryptPayloadComponentsActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.ExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> systemOpt = GetDefaultProtocolSystem();
            if (!systemOpt.HasValue || _state == null)
            {
                Sender.Tell(
                    Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.ExchangeType}")));
                return;
            }
            system = systemOpt.Value!;
        }

        Context.GetLogger().Info("[ENCRYPT_COMPONENTS] Using protocol system for type {0}", cmd.ExchangeType);

        Result<EncryptionComponentsResult, EcliptixProtocolFailure> result =
            _encryptionHandler.EncryptPayloadComponents(system, _state, cmd.Payload, cmd.ExchangeType);

        if (result.IsErr)
        {
            Sender.Tell(
                Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Err(
                    result.UnwrapErr()));
            return;
        }

        EncryptionComponentsResult encryptionResult = result.Unwrap();
        IActorRef? originalSender = Sender;

        if (encryptionResult.ShouldPersist)
        {
            Persist(encryptionResult.NewState, state =>
            {
                _state = state;
                originalSender.Tell(
                    Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok(
                        (encryptionResult.Header, encryptionResult.EncryptedPayload)));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = encryptionResult.NewState;
            originalSender.Tell(Result<(EnvelopeMetadata Header, byte[] EncryptedPayload), EcliptixProtocolFailure>.Ok(
                (encryptionResult.Header, encryptionResult.EncryptedPayload)));
        }
    }

    private void HandleDecryptWithHeader(DecryptPayloadWithHeaderActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.ExchangeType, out EcliptixProtocolSystem? system))
        {
            Option<EcliptixProtocolSystem> defaultSystemOpt = GetDefaultProtocolSystem();
            if (!defaultSystemOpt.HasValue || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.ExchangeType}")));
                return;
            }
            system = defaultSystemOpt.Value!;
        }

        Context.GetLogger().Info("[DECRYPT_WITH_HEADER] Using protocol system for type {0}", cmd.ExchangeType);

        Result<DecryptionResult, EcliptixProtocolFailure> result =
            _decryptionHandler.DecryptWithHeader(system, _state, cmd.Metadata, cmd.EncryptedPayload, cmd.ExchangeType);

        if (result.IsErr)
        {
            EcliptixProtocolFailure error = result.UnwrapErr();

            if (DecryptionHandler.ShouldClearSession(error))
            {
                Context.GetLogger()
                    .Warning(
                        "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
                DisposeAllSystems();
                _state = null;
                _currentExchangeType = null;

                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
            return;
        }

        DecryptionResult decryptionResult = result.Unwrap();

        if (decryptionResult.RequiresSessionClear)
        {
            Context.GetLogger()
                .Warning(
                    "AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
            DisposeAllSystems();
            _state = null;
            _currentExchangeType = null;

            SaveSnapshot(new EcliptixSessionState());
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Session authentication failed")));
            return;
        }

        IActorRef? originalSender = Sender;

        if (decryptionResult.ShouldPersist)
        {
            Persist(decryptionResult.NewState, state =>
            {
                _state = state;
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = decryptionResult.NewState;
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(decryptionResult.Plaintext));
        }
    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}
