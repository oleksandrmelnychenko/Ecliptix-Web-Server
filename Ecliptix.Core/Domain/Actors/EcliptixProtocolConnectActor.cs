using System.Linq;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;
using Unit = Ecliptix.Domain.Utilities.Unit;

namespace Ecliptix.Core.Domain.Actors;

public record DeriveSharedSecretActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public record CleanupProtocolForTypeActorEvent(PubKeyExchangeType ExchangeType);

public sealed record KeepAlive
{
    public static readonly KeepAlive Instance = new();

    private KeepAlive()
    {
    }
}

public sealed record RetryRecoveryMessage;

public class EcliptixProtocolConnectActor(uint connectId) : PersistentActor, IWithTimers
{
    public ITimerScheduler Timers { get; set; } = null!;
    
    public override string PersistenceId { get; } = $"connect-{connectId}";
    private const int SnapshotInterval = Constants.SnapshotInterval;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(1);
    private const int MaxRecoveryRetries = 3;
    
    private const string RecoveryRetryTimerKey = "recovery-retry";

    private EcliptixSessionState? _state;
    private readonly Dictionary<PubKeyExchangeType, EcliptixProtocolSystem> _protocolSystems = new();
    private int _recoveryRetryCount;

    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion;
    private bool _pendingSnapshotDeletion;

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
                Context.GetLogger().Info($"[RecoveryCompleted] Recovery finished for actor {Self.Path.Name}");
                if (_state != null)
                {
                    AttemptSystemRecreation();
                }
                else
                {
                    Context.GetLogger()
                        .Info($"[RecoveryCompleted] No previous session state found for connectId {connectId}");
                }

                return true;
            default:
                return false;
        }
    }

    protected override bool ReceiveCommand(object message)
    {
        Context.SetReceiveTimeout(IdleTimeout);

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
            case ClientDisconnectedActorEvent:
                SaveFinalSnapshot();
                return true;

            case SaveSnapshotSuccess success:
                if (_savingFinalSnapshot)
                {
                    Context.GetLogger().Info("Final snapshot saved successfully. Initiating cleanup operation.");
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
        EcliptixProtocolSystem? defaultSystem = GetDefaultProtocolSystem();
        if (defaultSystem == null || _state == null)
        {
            RestoreSecrecyChannelResponse notFoundReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = 0,
                SendingChainLength = 0
            };

            Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(notFoundReply));
            return;
        }

        Result<Unit, EcliptixProtocolFailure> stateValidation = ValidateRecoveredStateIntegrity();
        if (stateValidation.IsErr)
        {
            Context.GetLogger().Warning("State integrity validation failed: {Error}. Clearing session.",
                stateValidation.UnwrapErr().Message);

            RestoreSecrecyChannelResponse failureReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = 0,
                SendingChainLength = 0
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
                .Warning(
                    "Live system connection was cleared (likely due to fresh handshake detection). Clearing actor state.");

            RestoreSecrecyChannelResponse freshHandshakeReply = new()
            {
                Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionNotFound,
                ReceivingChainLength = 0,
                SendingChainLength = 0
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
            "Session restored - ConnectId: {ConnectId}, Sending: {SendingIdx}, Receiving: {ReceivingIdx}, LastPersist: {LastPersist}",
            connectId, reply.SendingChainLength, reply.ReceivingChainLength, lastPersistTime);

        Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(reply));
    }

    private Result<Unit, EcliptixProtocolFailure> ValidateRecoveredStateIntegrity()
    {
        if (_state?.RatchetState == null)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ActorStateNotFound("Ratchet state missing"));

        uint sendingIdx = _state.RatchetState.SendingStep.CurrentIndex;
        uint receivingIdx = _state.RatchetState.ReceivingStep.CurrentIndex;

        if (sendingIdx > 10_000_000 || receivingIdx > 10_000_000)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic(
                    $"Chain indices appear corrupted: sending={sendingIdx}, receiving={receivingIdx}"));

        if (_state.RatchetState.RootKey.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Root key missing from recovered state"));

        if (_state.RatchetState.SendingStep.ChainKey.IsEmpty ||
            _state.RatchetState.ReceivingStep.ChainKey.IsEmpty)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Chain keys missing from recovered state"));

        Google.Protobuf.ByteString sendingDhKey = _state.RatchetState.SendingStep.DhPublicKey;
        if (!sendingDhKey.IsEmpty && sendingDhKey.Length != 32)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Invalid DH key size: {sendingDhKey.Length}"));

        if (_state.RatchetState.NonceCounter > uint.MaxValue - Constants.NonceCounterWarningThreshold)
            return Result<Unit, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("Nonce counter near overflow"));

        return Result<Unit, EcliptixProtocolFailure>.Ok(Unit.Value);
    }


    private DateTime GetLastPersistenceTime()
    {
        return DateTime.UtcNow.AddMinutes(-((SnapshotSequenceNr % Constants.SnapshotModulus) * Constants.SnapshotMinuteMultiplier));
    }

    private static RatchetConfig GetRatchetConfigForExchangeType(PubKeyExchangeType exchangeType)
    {
        Context.GetLogger().Info($"[ACTOR] Selecting ratchet config for exchange type: {exchangeType}");
        
        return exchangeType switch
        {
            PubKeyExchangeType.DataCenterEphemeralConnect => new RatchetConfig
            {
                DhRatchetEveryNMessages = 10,
                MaxChainAge = TimeSpan.FromHours(6),
                MaxMessagesWithoutRatchet = 200
            },
            PubKeyExchangeType.VerificationFlowStream => new RatchetConfig
            {
                DhRatchetEveryNMessages = 20,  
                MaxChainAge = TimeSpan.FromMinutes(5),
                MaxMessagesWithoutRatchet = 100
            },
            PubKeyExchangeType.MessageDeliveryStream => new RatchetConfig
            {
                DhRatchetEveryNMessages = 50, 
                MaxChainAge = TimeSpan.FromMinutes(10),
                MaxMessagesWithoutRatchet = 200
            },
            PubKeyExchangeType.PresenceStream => new RatchetConfig
            {
                DhRatchetEveryNMessages = 100,
                MaxChainAge = TimeSpan.FromMinutes(15),
                MaxMessagesWithoutRatchet = 500
            },
            _ => RatchetConfig.Default
        };
    }

    protected override void PreStart()
    {
        Context.SetReceiveTimeout(IdleTimeout);
        base.PreStart();
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
        PubKeyExchangeType exchangeType = cmd.PubKeyExchange.OfType;
        if (_protocolSystems.TryGetValue(exchangeType, out EcliptixProtocolSystem? existingSystem) && _state != null)
        {
            Context.GetLogger()
                .Info($"[HandleInitialKeyExchange] Using existing recovered session for connectId {cmd.ConnectId}, type: {exchangeType}");
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
                    .Info("[HandleInitialKeyExchange] System detected fresh handshake - clearing actor state");
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

                    if (existingReplyResult.IsOk)
                    {
                        PubKeyExchange pubKeyReply = existingReplyResult.Unwrap();
                        Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(pubKeyReply)));
                    }
                    else
                    {
                        Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(existingReplyResult.UnwrapErr()));
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

        Context.GetLogger().Info($"[HandleInitialKeyExchange] Creating new session for connectId {cmd.ConnectId}, type: {exchangeType}");

        EcliptixSystemIdentityKeys identityKeys = EcliptixSystemIdentityKeys.Create(10).Unwrap();

        // Use type-specific config
        var config = GetRatchetConfigForExchangeType(exchangeType);
        EcliptixProtocolSystem system = new(identityKeys, config);

        Context.GetLogger().Info("[ACTOR] Created protocol with DH interval {0} for type {1}",
            config.DhRatchetEveryNMessages, exchangeType);
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
            _protocolSystems[exchangeType] = system; // Store by type
            originalSender.Tell(
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleEncrypt(EncryptPayloadActorEvent cmd)
    {
        // Route to the appropriate protocol system based on exchange type
        if (!_protocolSystems.TryGetValue(cmd.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            // Fallback to default system for backward compatibility
            system = GetDefaultProtocolSystem();
            if (system == null || _state == null)
            {
                Sender.Tell(
                    Result<CipherPayload, EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic($"No protocol system found for exchange type {cmd.PubKeyExchangeType}")));
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
            EcliptixProtocol.CreateStateFromSystem(_state, system);
        (EcliptixSessionState newState, CipherPayload ciphertext) = (newStateResult.Unwrap(), result.Unwrap());
        IActorRef? originalSender = Sender;

        Persist(newState, state =>
        {
            _state = state;
            originalSender.Tell(Result<CipherPayload, EcliptixProtocolFailure>.Ok(ciphertext));
            MaybeSaveSnapshot();
        });
    }

    private void HandleDecrypt(DecryptCipherPayloadActorEvent actorEvent)
    {
        // Route to the appropriate protocol system based on exchange type
        if (!_protocolSystems.TryGetValue(actorEvent.PubKeyExchangeType, out EcliptixProtocolSystem? system))
        {
            // Fallback to default system for backward compatibility
            system = GetDefaultProtocolSystem();
            if (system == null || _state == null)
            {
                Sender.Tell(
                    Result<byte[], EcliptixProtocolFailure>.Err(
                        EcliptixProtocolFailure.Generic($"No protocol system found for exchange type {actorEvent.PubKeyExchangeType}")));
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
                    .Warning("AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
                DisposeAllSystems();
                _state = null;

                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(_state, system);
        (EcliptixSessionState newState, byte[] plaintext) = (newStateResult.Unwrap(), result.Unwrap());
        IActorRef? originalSender = Sender;

        Persist(newState, state =>
        {
            _state = state;
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(plaintext));
            MaybeSaveSnapshot();
        });
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

    private void MaybeSaveSnapshot()
    {
        if (LastSequenceNr % SnapshotInterval == 0)
        {
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
        foreach (var system in _protocolSystems.Values)
        {
            system?.Dispose();
        }
        _protocolSystems.Clear();
    }
    
    private void AttemptSystemRecreation()
    {
        if (_state == null)
        {
            Context.GetLogger().Warning($"[Recovery] No state available for system recreation for connectId {connectId}");
            return;
        }

        Context.GetLogger().Debug($"[Recovery] Attempting system recreation (attempt {_recoveryRetryCount + 1}/{MaxRecoveryRetries}) for connectId {connectId}");

        Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult =
            EcliptixProtocol.RecreateSystemFromState(_state);

        if (systemResult.IsOk)
        {
            EcliptixProtocolSystem system = systemResult.Unwrap();
            // For recovery, assume DataCenterEphemeralConnect (main/default type)
            _protocolSystems[PubKeyExchangeType.DataCenterEphemeralConnect] = system;
            _recoveryRetryCount = 0;
            
            Context.GetLogger()
                .Info($"[Recovery] Protocol system successfully recreated for connectId {connectId}");
        }
        else
        {
            _recoveryRetryCount++;
            EcliptixProtocolFailure failure = systemResult.UnwrapErr();
            
            Context.GetLogger()
                .Warning($"[Recovery] Failed to recreate protocol system for connectId {connectId} (attempt {_recoveryRetryCount}/{MaxRecoveryRetries}): {failure.Message}");

            if (_recoveryRetryCount < MaxRecoveryRetries)
            {
                // Schedule retry with exponential backoff
                int delaySeconds = (int)Math.Pow(2, _recoveryRetryCount - 1) * 5; // 5s, 10s, 20s
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
                    .Error($"[Recovery] Max recovery retries exceeded for connectId {connectId}. Continuing with degraded functionality.");
                
                DisposeAllSystems();
                
                SaveSnapshot(_state);
            }
        }
    }

    private EcliptixProtocolSystem? GetDefaultProtocolSystem()
    {
        // Try to get DataCenterEphemeralConnect first (most common)
        if (_protocolSystems.TryGetValue(PubKeyExchangeType.DataCenterEphemeralConnect, out EcliptixProtocolSystem? defaultSystem))
        {
            return defaultSystem;
        }
        
        // If none found, return the first available system
        return _protocolSystems.Values.FirstOrDefault();
    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}