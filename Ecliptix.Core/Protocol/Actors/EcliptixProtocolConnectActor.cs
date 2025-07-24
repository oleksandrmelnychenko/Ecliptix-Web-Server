using Akka.Actor;
using Akka.Event;
using Akka.Persistence;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.ProtocolState;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol.Actors;

public record DeriveSharedSecretActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public sealed record KeepAlive
{
    public static readonly KeepAlive Instance = new();

    private KeepAlive()
    {
    }
}

public class EcliptixProtocolConnectActor(uint connectId) : PersistentActor
{
    public override string PersistenceId { get; } = $"connect-{connectId}";
    private const int SnapshotInterval = 50;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(1);

    private EcliptixSessionState? _state;
    private EcliptixProtocolSystem? _liveSystem;
    
    private bool _savingFinalSnapshot;
    private bool _pendingMessageDeletion = false;
    private bool _pendingSnapshotDeletion = false;

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
                    Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult =
                        EcliptixProtocol.RecreateSystemFromState(_state);
                    if (systemResult.IsOk)
                    {
                        _liveSystem = systemResult.Unwrap();
                        Context.GetLogger().Info($"[RecoveryCompleted] Protocol system successfully recreated for connectId {connectId}");
                    }
                    else
                    {
                        Context.GetLogger().Warning($"[RecoveryCompleted] Failed to recreate protocol system for connectId {connectId}");
                        Context.Stop(Self);
                    }
                }
                else
                {
                    Context.GetLogger().Info($"[RecoveryCompleted] No previous session state found for connectId {connectId}");
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
           
            // This is now the ONLY automatic shutdown trigger.
            case ReceiveTimeout _:
                SaveFinalSnapshot();
                return true;

            // Streams only.
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
                if(_savingFinalSnapshot && _pendingMessageDeletion)
                {
                    _pendingMessageDeletion = false;
                    TryCompleteShutdown();
                }
                
                return true;
            case DeleteSnapshotsSuccess success:
                if(_savingFinalSnapshot && _pendingSnapshotDeletion)
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
            Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic("pfhSession not ready or in an invalid state.")));
            return;
        }

        RestoreSecrecyChannelResponse reply = new()
        {
            ReceivingChainLength = _state.RatchetState.ReceivingStep.CurrentIndex,
            SendingChainLength = _state.RatchetState.SendingStep.CurrentIndex,
            Status = RestoreSecrecyChannelResponse.Types.RestoreStatus.SessionResumed
        };

        Sender.Tell(Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Ok(reply));
    }

    protected override void PreStart()
    {
        Context.SetReceiveTimeout(IdleTimeout);
        base.PreStart();
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
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
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(result.UnwrapErr()));
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

    private bool IsSessionReady(out EcliptixSessionState currentState)
    {
        currentState = _state!;
        return _state != null;
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
        if(!_pendingMessageDeletion && !_pendingSnapshotDeletion)
        {
            Context.GetLogger().Info("All cleanup operations completed. Stopping actor.");
            Context.Stop(Self);
        }
    }

    protected override void PostStop()
    {
        _liveSystem?.Dispose();
        base.PostStop();
    }

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}