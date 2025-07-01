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
        string actorName = $"connect-{connectId}";

        IActorRef connectActor = Context.Child(actorName);

        if (connectActor.IsNobody())
        {
            try
            {
                connectActor = Context.ActorOf(EcliptixProtocolConnectActor.Build(connectId), actorName);
                Context.Watch(connectActor);
            }
            catch (Exception ex)
            {
                EcliptixProtocolFailure failure =
                    EcliptixProtocolFailure.ActorNotCreated($"Failed to create actor for connectId: {connectId}", ex);
                Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(failure));
                return;
            }
        }

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

        if (connectActor.IsNobody())
        {
            object errorResult = message.Payload switch
            {
                EncryptPayloadActorEvent => Result<CipherPayload, EcliptixProtocolFailure>.Err(
                    CreateNotFoundError(connectId)),
                DecryptCipherPayloadActorEvent => Result<byte[], EcliptixProtocolFailure>.Err(
                    CreateNotFoundError(connectId)),
                RestoreAppDeviceSecrecyChannelState => Result<RestoreSecrecyChannelResponse, EcliptixProtocolFailure>.Err(
                    CreateNotFoundError(connectId)),
                KeepAlive => Akka.Done.Instance,
                _ => Result<object, EcliptixProtocolFailure>.Err(CreateNotFoundError(connectId))
            };

            if (message.Payload is not KeepAlive)
                Sender.Tell(errorResult);
        }
        else
        {
            if (message.Payload is KeepAlive)
            {
                connectActor.Tell(message.Payload, ActorRefs.NoSender);
            }
            else
            {
                object? result =
                    await connectActor.Ask(message.Payload,
                        timeout: TimeSpan.FromSeconds(30));
                Sender.Tell(result);
            }
        }
    }

    private static EcliptixProtocolFailure CreateNotFoundError(uint connectId)
    {
        return EcliptixProtocolFailure.ActorRefNotFound(
            $"Secure session with Id:{connectId} not found or has timed out. Please re-establish the connection.");
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolSystemActor());
    }
}