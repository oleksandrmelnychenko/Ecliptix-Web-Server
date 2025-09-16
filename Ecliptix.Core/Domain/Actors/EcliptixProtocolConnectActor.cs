using System.Linq;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Domain.Events;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;
using Unit = Ecliptix.Domain.Utilities.Unit;

namespace Ecliptix.Core.Domain.Actors;

public class EcliptixProtocolConnectActor(uint connectId) : PersistentActor, IWithTimers
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
            case DeriveSharedSecretActorEvent cmd:
                HandleInitialKeyExchange(cmd);
                return true;
            case EncryptPayloadActorEvent cmd:
                HandleEncrypt(cmd);
                return true;
            case DecryptCipherPayloadActorEvent cmd:
                HandleDecrypt(cmd);
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
                if (!_savingFinalSnapshot || !_pendingMessageDeletion) return true;
                _pendingMessageDeletion = false;
                TryCompleteShutdown();

                return true;
            case DeleteSnapshotsSuccess:
                if (!_savingFinalSnapshot || !_pendingSnapshotDeletion) return true;
                _pendingSnapshotDeletion = false;
                TryCompleteShutdown();

                return true;
            default:
                return false;
        }
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

        EcliptixProtocolSystem? defaultSystem = GetDefaultProtocolSystem();
        if (defaultSystem == null || _state == null)
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

        Result<Unit, EcliptixProtocolFailure> stateValidation = ValidateRecoveredStateIntegrity();
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
                .Warning(ActorConstants.LogMessages.LiveConnectionCleared);

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
            ActorConstants.LogMessages.SessionRestored,
            connectId, reply.SendingChainLength, reply.ReceivingChainLength, lastPersistTime);

        Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(reply));
    }

    private Result<Unit, EcliptixProtocolFailure> ValidateRecoveredStateIntegrity()
    {
        if (_state?.RatchetState == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ActorStateNotFound(ActorConstants.ErrorMessages.RatchetStateMissing));

        uint sendingIdx = _state.RatchetState.SendingStep.CurrentIndex;
        uint receivingIdx = _state.RatchetState.ReceivingStep.CurrentIndex;

        if (sendingIdx > ActorConstants.Validation.MaxChainIndex ||
            receivingIdx > ActorConstants.Validation.MaxChainIndex)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Chain indices appear corrupted: sending={sendingIdx}, receiving={receivingIdx}"));

        if (_state.RatchetState.RootKey.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(ActorConstants.ErrorMessages.RootKeyMissing));

        if (_state.RatchetState.SendingStep.ChainKey.IsEmpty ||
            _state.RatchetState.ReceivingStep.ChainKey.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(ActorConstants.ErrorMessages.ChainKeysMissing));

        Google.Protobuf.ByteString sendingDhKey = _state.RatchetState.SendingStep.DhPublicKey;
        if (!sendingDhKey.IsEmpty && sendingDhKey.Length != ActorConstants.Validation.ExpectedDhKeySize)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Invalid DH key size: {sendingDhKey.Length}"));

        if (_state.RatchetState.NonceCounter > uint.MaxValue - ActorConstants.Constants.NonceCounterWarningThreshold)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(ActorConstants.ErrorMessages.NonceCounterOverflow));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }

    private DateTime GetLastPersistenceTime()
    {
        return DateTime.UtcNow.AddMinutes(-((SnapshotSequenceNr % ActorConstants.Constants.SnapshotModulus) *
                                            ActorConstants.Constants.SnapshotMinuteMultiplier));
    }

    private static RatchetConfig GetRatchetConfigForExchangeType(PubKeyExchangeType exchangeType)
    {
        Context.GetLogger().Info(ActorConstants.LogMessages.SelectingRatchetConfig, exchangeType);

        return exchangeType switch
        {
            PubKeyExchangeType.DataCenterEphemeralConnect => new RatchetConfig
            {
                DhRatchetEveryNMessages = ActorConstants.Constants.RatchetMessagesInterval10,
                MaxChainAge = TimeSpan.FromHours(ActorConstants.Constants.MaxChainAge6Hours),
                MaxMessagesWithoutRatchet = ActorConstants.Constants.MaxMessagesWithoutRatchet200
            },
            PubKeyExchangeType.ServerStreaming => new RatchetConfig
            {
                DhRatchetEveryNMessages = ActorConstants.Constants.RatchetMessagesInterval20,
                MaxChainAge = TimeSpan.FromMinutes(ActorConstants.Constants.MaxChainAge5Minutes),
                MaxMessagesWithoutRatchet = ActorConstants.Constants.MaxMessagesWithoutRatchet100
            },
            _ => RatchetConfig.Default
        };
    }

    protected override void PreStart()
    {
        base.PreStart();
        Context.GetLogger().Info("[PROTOCOL_ACTOR] Starting and subscribing to ProtocolCleanupRequiredEvent - ConnectId: {0}", connectId);
        Context.System.EventStream.Subscribe(Self, typeof(ProtocolCleanupRequiredEvent));
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
                        // No timeout for ServerStreaming - controlled by VerificationFlow
                        Context.SetReceiveTimeout(null);
                        Context.GetLogger().Info("[PROTOCOL] ServerStreaming - no timeout, controlled by VerificationFlow for ConnectId {0}", cmd.ConnectId);
                    }
                    else
                    {
                        // All other types (DataCenterEphemeralConnect, etc.) use timeout
                        Context.SetReceiveTimeout(IdleTimeout);
                        Context.GetLogger().Info("[PROTOCOL] {0} - using idle timeout for ConnectId {1}", exchangeType, cmd.ConnectId);
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

        RatchetConfig ratchetConfig = GetRatchetConfigForExchangeType(exchangeType);
        EcliptixProtocolSystem system = new(identityKeys, ratchetConfig);

        Context.GetLogger().Info(ActorConstants.LogMessages.CreatedProtocolWithInterval,
            ratchetConfig.DhRatchetEveryNMessages, exchangeType);
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

            // Set timeout based on exchange type
            if (exchangeType == PubKeyExchangeType.ServerStreaming)
            {
                Context.SetReceiveTimeout(null); // No timeout for ServerStreaming
            }
            else
            {
                Context.SetReceiveTimeout(IdleTimeout); // Timeout for DataCenterEphemeralConnect and others
            }

            originalSender.Tell(
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleEncrypt(EncryptPayloadActorEvent cmd)
    {
        if (!_protocolSystems.TryGetValue(cmd.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            system = GetDefaultProtocolSystem();
            if (system == null || _state == null)
            {
                Sender.Tell(
                    Result<CipherPayload, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {cmd.PubKeyExchangeType}")));
                return;
            }
        }

        Context.GetLogger().Info("[ENCRYPT] Using protocol system for type {0}", cmd.PubKeyExchangeType);
        Result<CipherPayload, EcliptixProtocolFailure> result = system.ProduceOutboundMessage(cmd.Payload);
        if (result.IsErr)
        {
            Sender.Tell(Result<CipherPayload, EcliptixProtocolFailure>.Err(result.UnwrapErr()));
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(_state ?? new EcliptixSessionState(), system);
        (EcliptixSessionState newState, CipherPayload ciphertext) = (newStateResult.Unwrap(), result.Unwrap());
        IActorRef? originalSender = Sender;

        bool shouldPersist = cmd.PubKeyExchangeType != PubKeyExchangeType.ServerStreaming;

        if (shouldPersist)
        {
            Persist(newState, state =>
            {
                _state = state;
                originalSender.Tell(Result<CipherPayload, EcliptixProtocolFailure>.Ok(ciphertext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newState;
            originalSender.Tell(Result<CipherPayload, EcliptixProtocolFailure>.Ok(ciphertext));
        }
    }

    private void HandleDecrypt(DecryptCipherPayloadActorEvent actorEvent)
    {
        if (!_protocolSystems.TryGetValue(actorEvent.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            system = GetDefaultProtocolSystem();
            if (system == null || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic(
                            $"No protocol system found for exchange type {actorEvent.PubKeyExchangeType}")));
                return;
            }
        }

        Context.GetLogger().Info("[DECRYPT] Using protocol system for type {0}", actorEvent.PubKeyExchangeType);
        Result<byte[], EcliptixProtocolFailure> result = system.ProcessInboundMessage(actorEvent.CipherPayload);
        if (result.IsErr)
        {
            EcliptixProtocolFailure error = result.UnwrapErr();
            if (error.FailureType == EcliptixProtocolFailureType.StateMissing &&
                error.Message.Contains("Session authentication failed"))
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

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(_state ?? new EcliptixSessionState(), system);
        (EcliptixSessionState newState, byte[] plaintext) = (newStateResult.Unwrap(), result.Unwrap());
        IActorRef? originalSender = Sender;

        bool shouldPersist = actorEvent.PubKeyExchangeType == PubKeyExchangeType.DataCenterEphemeralConnect;

        if (shouldPersist)
        {
            Persist(newState, state =>
            {
                _state = state;
                originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(plaintext));
                MaybeSaveSnapshot();
            });
        }
        else
        {
            _state = newState;
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(plaintext));
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
            .Info("[SESSION_CLEANUP] Received cleanup request for verification session expiry - ConnectId: {0}",
                connectId);

        if (_protocolSystems.TryGetValue(PubKeyExchangeType.ServerStreaming,
                out EcliptixProtocolSystem? streamingSystem))
        {
            Context.GetLogger().Info("[SESSION_CLEANUP] Disposing SERVER_STREAMING protocol system for ConnectId: {0}",
                connectId);
            streamingSystem?.Dispose();
            _protocolSystems.Remove(PubKeyExchangeType.ServerStreaming);

            if (_currentExchangeType == PubKeyExchangeType.ServerStreaming)
            {
                _currentExchangeType = null;
                Context.GetLogger().Info("[SESSION_CLEANUP] Cleared current exchange type for ConnectId: {0}",
                    connectId);
            }
        }

        if (_protocolSystems.Count == 0)
        {
            Context.GetLogger()
                .Info("[SESSION_CLEANUP] No remaining protocols - terminating actor for ConnectId: {0}", connectId);
            Context.Stop(Self);
        }
        else
        {
            Context.GetLogger().Info("[SESSION_CLEANUP] {0} protocol(s) remain active for ConnectId: {1}",
                _protocolSystems.Count, connectId);
        }
    }

    private void MaybeSaveSnapshot()
    {
        if (LastSequenceNr % SnapshotInterval == 0)
        {
            if (_currentExchangeType != PubKeyExchangeType.DataCenterEphemeralConnect)
                return;

            SaveSnapshot(_state);
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

    protected override void PostStop()
    {
        Timers.CancelAll();
        DisposeAllSystems();
        base.PostStop();
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

        Context.GetLogger()
            .Debug(
                $"[Recovery] Attempting system recreation (attempt {_recoveryRetryCount + 1}/{MaxRecoveryRetries}) for connectId {connectId}");

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

    private EcliptixProtocolSystem? GetDefaultProtocolSystem()
    {
        if (_protocolSystems.TryGetValue(PubKeyExchangeType.DataCenterEphemeralConnect,
                out EcliptixProtocolSystem? defaultSystem))
        {
            return defaultSystem;
        }

        return _protocolSystems.Values.FirstOrDefault();
    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}