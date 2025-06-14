using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Serilog;

namespace Ecliptix.Core.Protocol.Actors;

public record BeginAppDeviceEphemeralConnectActorEvent(PubKeyExchange PubKeyExchange, uint UniqueConnectId);

public record DecryptCipherPayloadActorActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptPayloadActorEvent(
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record ForwardToConnectActorEvent(uint ConnectId, object Payload);

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
            Log.Warning("Supervised session actor {ActorPath} has terminated. Its resources are released.",
                t.ActorRef.Path);
        });
    }

    private async Task ProcessNewSessionRequest(BeginAppDeviceEphemeralConnectActorEvent actorEvent)
    {
        uint connectId = actorEvent.UniqueConnectId;
        string actorName = $"connect-{connectId}";

        Log.Information("[ShieldPro] Beginning 3DH exchange for Session ID: {ConnectId}", connectId);

        IActorRef connectActor = Context.Child(actorName);

        if (connectActor.IsNobody())
        {
            Log.Information("Creating new session actor for ConnectId {ConnectId} with name {ActorName}", connectId,
                actorName);
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
        else
        {
            Log.Information("Found existing session actor for ConnectId {ConnectId}. Re-initializing handshake",
                connectId);
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
            Log.Warning("Message received for a non-existent or timed-out session: {ConnectId}", connectId);
            object errorResult = message.Payload switch
            {
                EncryptPayloadActorEvent => Result<CipherPayload, EcliptixProtocolFailure>.Err(
                    CreateNotFoundError(connectId)),
                DecryptCipherPayloadActorActorEvent => Result<byte[], EcliptixProtocolFailure>.Err(
                    CreateNotFoundError(connectId)),
                _ => Result<object, EcliptixProtocolFailure>.Err(CreateNotFoundError(connectId))
            };
            Sender.Tell(errorResult);
        }
        else
        {
            object? result = await connectActor.Ask<object>(message.Payload);
            Sender.Tell(result);
        }
    }

    private static EcliptixProtocolFailure CreateNotFoundError(uint connectId)
    {
        return EcliptixProtocolFailure.ActorRefNotFound(
            $"Secure session with Id:{connectId} not found or has timed out. Please re-establish the connection.");
    }

    protected override void PreStart()
    {
        Log.Information("Main EcliptixProtocolSystemActor '{ActorPath}' is up and running", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolSystemActor());
    }
}