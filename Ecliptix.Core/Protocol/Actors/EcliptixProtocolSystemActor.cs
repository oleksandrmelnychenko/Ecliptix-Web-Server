using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Serilog;

namespace Ecliptix.Core.Protocol.Actors;

public record BeginAppDeviceEphemeralConnectActorEvent(PubKeyExchange PubKeyExchange, uint UniqueConnectId);

public record DecryptCipherPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record ClientDisconnectedActorEvent(uint ConnectId);

public record ForwardToConnectActorEvent(uint ConnectId, object Payload);

public record RestoreAppDeviceSecrecyChannelState;

public class EcliptixProtocolSystemActor : ReceiveActor
{
    public EcliptixProtocolSystemActor()
    {
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectActorEvent>(ProcessNewSessionRequest);
        ReceiveAsync<ForwardToConnectActorEvent>(ProcessForwarding);
        Receive<Terminated>(t =>
        {
            Log.Warning("Supervised session actor {ActorPath} has terminated. Its resources are released",
                t.ActorRef.Path);
        });

        Receive<ClientDisconnectedActorEvent>(cmd =>
        {
            string actorName = $"connect-{cmd.ConnectId}";
            IActorRef connectActor = Context.Child(actorName);
            if (!connectActor.IsNobody())
            {
                connectActor.Forward(cmd);
            }
        });
    }

    private async Task ProcessNewSessionRequest(BeginAppDeviceEphemeralConnectActorEvent actorEvent)
    {
        uint connectId = actorEvent.UniqueConnectId;
        Result<IActorRef, EcliptixProtocolFailure> connectActorResult = GetOrCreateConnectActor(connectId);
        
        if (connectActorResult.IsErr)
        {
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(connectActorResult.UnwrapErr()));
            return;
        }

        IActorRef connectActor = connectActorResult.Unwrap();
        DeriveSharedSecretActorEvent deriveSharedSecretEvent = new(connectId, actorEvent.PubKeyExchange);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> result =
            await connectActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(deriveSharedSecretEvent);

        Sender.Tell(result);
    }

    private async Task ProcessForwarding(ForwardToConnectActorEvent message)
    {
        uint connectId = message.ConnectId;
        string actorName = $"connect-{connectId}";
        IActorRef connectActor = Context.Child(actorName);

        if (connectActor.IsNobody() && message.Payload is not KeepAlive)
        {
            Result<IActorRef, EcliptixProtocolFailure> connectActorResult = GetOrCreateConnectActor(connectId);
            if (connectActorResult.IsErr)
            {
                Sender.Tell(Result<object, EcliptixProtocolFailure>.Err(connectActorResult.UnwrapErr()));
                return;
            }
            connectActor = connectActorResult.Unwrap();
        }

        if (message.Payload is KeepAlive)
        {
            connectActor.Tell(message.Payload, ActorRefs.NoSender);
        }
        else
        {
            object? result = await connectActor.Ask(message.Payload);
            Sender.Tell(result);
        }
    }

    private Result<IActorRef, EcliptixProtocolFailure> GetOrCreateConnectActor(uint connectId)
    {
        string actorName = $"connect-{connectId}";
        IActorRef connectActor = Context.Child(actorName);

        if (connectActor.IsNobody())
        {
            try
            {
                connectActor = Context.ActorOf(EcliptixProtocolConnectActor.Build(connectId), actorName);
                Context.Watch(connectActor);
                return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
            }
            catch (Exception ex)
            {
                return Result<IActorRef, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.ActorNotCreated($"Failed to create actor for connectId: {connectId}", ex));
            }
        }

        return Result<IActorRef, EcliptixProtocolFailure>.Ok(connectActor);
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolSystemActor());
    }
}