using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Serilog;

namespace Ecliptix.Core.Protocol.Actors;

public record BeginAppDeviceEphemeralConnectActorEvent(PubKeyExchange PubKeyExchange, uint UniqueConnectId = 0);

public record DecryptCipherPayloadActorActorEvent(
    uint ConnectId,
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptPayloadActorCommand(
    uint ConnectId,
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record CreateConnectActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public class EcliptixProtocolSystemActor : ReceiveActor
{
    private readonly ConcurrentDictionary<uint, IActorRef> _connectActorRefs = new();

    public EcliptixProtocolSystemActor()
    {
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectActorEvent>(ProcessBeginAppDeviceEphemeralConnect);
        ReceiveAsync<DecryptCipherPayloadActorActorEvent>(HandleDecryptCipherPayload);
        ReceiveAsync<EncryptPayloadActorCommand>(HandleEncryptCipherPayload);
        ReceiveAsync<CreateConnectActorEvent>(ProcessCreateConnect);
    }

    private async Task ProcessBeginAppDeviceEphemeralConnect(BeginAppDeviceEphemeralConnectActorEvent actorEvent)
    {
        uint connectId = actorEvent.UniqueConnectId;
        PubKeyExchange peerPubKeyExchange = actorEvent.PubKeyExchange;
        PubKeyExchangeState exchangeType = actorEvent.PubKeyExchange.State;

        Log.Information("[ShieldPro] Beginning exchange {ExchangeType}, generated Session ID: {ConnectId}",
            exchangeType, connectId);

        CreateConnectActorEvent createConnectActorEvent = new(connectId, peerPubKeyExchange);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> result =
            await CreateConnectActorAndDeriveSecret(createConnectActorEvent);

        Sender.Tell(result);
    }

    private async Task<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>> CreateConnectActorAndDeriveSecret(
        CreateConnectActorEvent actorEvent)
    {
        uint connectId = actorEvent.ConnectId;
        PubKeyExchange exchangeType = actorEvent.PubKeyExchange;

        Result<IActorRef, EcliptixProtocolFailure> actorCreationalResult =
            Result<IActorRef, EcliptixProtocolFailure>.Try(() =>
                {
                    IActorRef actorRef = Context.ActorOf(
                        EcliptixProtocolConnectActor.Build(),
                        $"connect-{connectId}");
                    return actorRef;
                },
                err => EcliptixProtocolFailure.ActorNotCreated($"Failed to create actor for connectId: {connectId}",
                    err));

        if (actorCreationalResult.IsErr)
            return Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(actorCreationalResult.UnwrapErr());

        IActorRef actorRef = actorCreationalResult.Unwrap();
        _connectActorRefs.TryAdd(connectId, actorRef);

        DeriveSharedSecretActorEvent deriveSharedSecretActorEvent = new(connectId, exchangeType);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> deriveSharedSecretResult =
            await actorRef.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(deriveSharedSecretActorEvent);

        return deriveSharedSecretResult;
    }

    private async Task ProcessCreateConnect(CreateConnectActorEvent actorEvent)
    {
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> result =
            await CreateConnectActorAndDeriveSecret(actorEvent);
        Sender.Tell(result);
    }

    private async Task HandleEncryptCipherPayload(EncryptPayloadActorCommand actorCommand)
    {
        uint connectId = actorCommand.ConnectId;

        if (_connectActorRefs.TryGetValue(connectId, out IActorRef? actorRef))
        {
            Result<CipherPayload, EcliptixProtocolFailure> result =
                await actorRef.Ask<Result<CipherPayload, EcliptixProtocolFailure>>(actorCommand);
            Sender.Tell(result);
        }
        else
        {
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ActorRefNotFound($"Connect actor with Id:{connectId} not found")));
        }
    }

    private async Task HandleDecryptCipherPayload(DecryptCipherPayloadActorActorEvent actorActorEvent)
    {
        uint connectId = actorActorEvent.ConnectId;

        if (_connectActorRefs.TryGetValue(connectId, out IActorRef? actorRef))
        {
            Result<byte[], EcliptixProtocolFailure> result =
                await actorRef.Ask<Result<byte[], EcliptixProtocolFailure>>(actorActorEvent);
            Sender.Tell(result);
        }
        else
        {
            Sender.Tell(Result<byte[], EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.ActorRefNotFound($"Connect actor with Id:{connectId} not found")));
        }
    }

    protected override void PreStart()
    {
        Log.Information("MainShieldPro actor '{ActorPath}' is up and running", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolSystemActor());
    }
}