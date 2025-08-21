using System.Security.Cryptography;
using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Protobuf.Common;
using Ecliptix.Protobuf.ProtocolState;
using LanguageExt;
using Unit = Ecliptix.Domain.Utilities.Unit;

namespace Ecliptix.Core.Domain.Actors;

public record DeriveSharedSecretActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

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
    private EcliptixProtocolSystem? _liveSystem;
    private int _recoveryRetryCount = 0;
    private EcliptixSessionState? _lastKnownGoodState;

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
            case RestoreAppDeviceSecrecyChannelState:
                HandleRestoreSecrecyChannelState();
                return true;
            case KeepAlive:
                return true;
            case RetryRecoveryMessage:
                AttemptSystemRecreation();
                return true;

            case ReceiveTimeout _:
                SaveFinalSnapshot();
                return true;
            case ClientDisconnectedActorEvent _:
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
            case SaveSnapshotFailure failure:
                return true;

            case DeleteMessagesSuccess success:
                if (_savingFinalSnapshot && _pendingMessageDeletion)
                {
                    _pendingMessageDeletion = false;
                    TryCompleteShutdown();
                }

                return true;
            case DeleteSnapshotsSuccess success:
                if (_savingFinalSnapshot && _pendingSnapshotDeletion)
                {
                    _pendingSnapshotDeletion = false;
                    TryCompleteShutdown();
                }

                return true;
            default:
                return false;
        }
    }

    private void HandleRestoreSecrecyChannelState()
    {
        if (_liveSystem == null || _state == null)
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

            _liveSystem?.Dispose();
            _liveSystem = null;
            _state = null;
            SaveSnapshot(new EcliptixSessionState());
            return;
        }

        try
        {
            _liveSystem.GetConnection();
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

            _liveSystem?.Dispose();
            _liveSystem = null;
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

    protected override void PreStart()
    {
        Context.SetReceiveTimeout(IdleTimeout);
        base.PreStart();
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
        if (_liveSystem != null && _state != null)
        {
            Context.GetLogger()
                .Info($"[HandleInitialKeyExchange] Using existing recovered session for connectId {cmd.ConnectId}");
            Result<PubKeyExchange, EcliptixProtocolFailure> existingReplyResult =
                _liveSystem.ProcessAndRespondToPubKeyExchange(cmd.ConnectId, cmd.PubKeyExchange);

            bool sessionStillValid = true;
            try
            {
                _liveSystem.GetConnection();
            }
            catch (InvalidOperationException)
            {
                Context.GetLogger()
                    .Info("[HandleInitialKeyExchange] System detected fresh handshake - clearing actor state");
                _liveSystem?.Dispose();
                _liveSystem = null;
                _state = null;
                sessionStillValid = false;
                SaveSnapshot(new EcliptixSessionState());
            }

            if (sessionStillValid)
            {
                if (existingReplyResult.IsOk)
                {
                    Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
                        EcliptixProtocol.CreateStateFromSystem(_state!, _liveSystem!);
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

        Context.GetLogger().Info($"[HandleInitialKeyExchange] Creating new session for connectId {cmd.ConnectId}");
        EcliptixSystemIdentityKeys identityKeys = EcliptixSystemIdentityKeys.Create(10).Unwrap();
        EcliptixProtocolSystem system = new(identityKeys);
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
            _liveSystem = system;
            originalSender.Tell(
                Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(new DeriveSharedSecretReply(reply)));
            MaybeSaveSnapshot();
        });
    }

    private void HandleEncrypt(EncryptPayloadActorEvent cmd)
    {
        if (_liveSystem == null || _state == null)
        {
            Sender.Tell(
                Result<CipherPayload, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic("Session not ready.")));
            return;
        }

        Result<CipherPayload, EcliptixProtocolFailure> result = _liveSystem.ProduceOutboundMessage(cmd.Payload);
        if (result.IsErr)
        {
            Sender.Tell(Result<CipherPayload, EcliptixProtocolFailure>.Err(result.UnwrapErr()));
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(_state, _liveSystem);
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
        if (_liveSystem == null || _state == null)
        {
            Sender.Tell(
                Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.Generic("Session not ready.")));
            return;
        }

        Result<byte[], EcliptixProtocolFailure> result = _liveSystem.ProcessInboundMessage(actorEvent.CipherPayload);
        if (result.IsErr)
        {
            EcliptixProtocolFailure error = result.UnwrapErr();
            if (error.FailureType == EcliptixProtocolFailureType.StateMissing &&
                error.Message.Contains("Session authentication failed"))
            {
                Context.GetLogger()
                    .Warning("AD compatibility strategies exhausted - this indicates client-server cryptographic context mismatch. Clearing session to force fresh handshake.");
                _liveSystem?.Dispose();
                _liveSystem = null;
                _state = null;

                SaveSnapshot(new EcliptixSessionState());
            }

            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(error));
            return;
        }

        Result<EcliptixSessionState, EcliptixProtocolFailure> newStateResult =
            EcliptixProtocol.CreateStateFromSystem(_state, _liveSystem);
        (EcliptixSessionState newState, byte[] plaintext) = (newStateResult.Unwrap(), result.Unwrap());
        IActorRef? originalSender = Sender;

        Persist(newState, state =>
        {
            _state = state;
            originalSender.Tell(Result<byte[], EcliptixProtocolFailure>.Ok(plaintext));
            MaybeSaveSnapshot();
        });
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
        // Cancel any active timers
        Timers.CancelAll();
        
        _liveSystem?.Dispose();
        base.PostStop();
    }
    
    /// <summary>
    /// Attempts to recreate the protocol system with retry logic and partial state preservation
    /// </summary>
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
            _liveSystem = systemResult.Unwrap();
            _lastKnownGoodState = _state;
            _recoveryRetryCount = 0; // Reset retry count on success
            
            Context.GetLogger()
                .Info($"[Recovery] Protocol system successfully recreated for connectId {connectId}");
        }
        else
        {
            _recoveryRetryCount++;
            var failure = systemResult.UnwrapErr();
            
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
                // Max retries exceeded - preserve partial state and continue with degraded functionality
                Context.GetLogger()
                    .Error($"[Recovery] Max recovery retries exceeded for connectId {connectId}. Continuing with degraded functionality.");
                
                // Clean up any partial system state but preserve the session state for potential manual recovery
                _liveSystem?.Dispose();
                _liveSystem = null;
                
                // Save a recovery failure marker but preserve original state for debugging
                // Note: Preserve the state as-is for potential manual recovery
                SaveSnapshot(_state);
            }
        }
    }

    /// <summary>
    /// AOT-compatible Props builder - lambda captures parameter but no closures
    /// </summary>
    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}