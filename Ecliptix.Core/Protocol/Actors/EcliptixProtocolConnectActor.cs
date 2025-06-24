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

public class EcliptixProtocolConnectActor(uint connectId) : PersistentActor
{
    public override string PersistenceId { get; } = $"connect-{connectId}";
    private const int SnapshotInterval = 50;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(15);

    private EcliptixSessionState? _state;
    private readonly ILoggingAdapter _log = Context.GetLogger();

    private EcliptixProtocolSystem? _liveSystem;

    protected override bool ReceiveRecover(object message)
    {
        switch (message)
        {
            case SnapshotOffer { Snapshot: EcliptixSessionState state } offer:
                _state = state;
                return true;

            case EcliptixSessionState state:
                _state = state;
                return true;

            case RecoveryCompleted:
                if (_state != null)
                {
                    Result<EcliptixProtocolSystem, EcliptixProtocolFailure> systemResult =
                        EcliptixProtocol.RecreateSystemFromState(_state);
                    if (systemResult.IsOk)
                    {
                        _liveSystem = systemResult.Unwrap();
                    }
                    else
                    {
                        Context.Stop(Self);
                    }
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
            case SaveSnapshotSuccess success:
                DeleteMessages(success.Metadata.SequenceNr);
                DeleteSnapshots(new SnapshotSelectionCriteria(success.Metadata.SequenceNr - 1));
                return true;
            case SaveSnapshotFailure failure:
                return true;
            case ReceiveTimeout _:
                Context.Stop(Self);
                return true;
            default:
                return false;
        }
    }

    protected override void PreStart()
    {
        Context.SetReceiveTimeout(IdleTimeout);
        base.PreStart();
    }

    private void HandleInitialKeyExchange(DeriveSharedSecretActorEvent cmd)
    {
        if (_liveSystem != null)
        {
            _log.Warning("Duplicate handshake request for existing session {0}. Ignoring.", PersistenceId);
            return;
        }

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

    private void HandleDecrypt(DecryptCipherPayloadActorEvent cmd)
    {
        if (_liveSystem == null || _state == null)
        {
            Sender.Tell(
                Result<byte[], EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.Generic("Session not ready.")));
            return;
        }

        Result<byte[], EcliptixProtocolFailure> result = _liveSystem.ProcessInboundMessage(cmd.CipherPayload);
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

    public static Props Build(uint connectId) => Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}