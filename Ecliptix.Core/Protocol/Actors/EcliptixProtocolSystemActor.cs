using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol.Actors;

public record BeginAppDeviceEphemeralConnectCommand(PubKeyExchange PubKeyExchange, uint UniqueConnectId = 0);

public record DecryptCipherPayloadActorCommand(
    uint ConnectId,
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptPayloadActorCommand(
    uint ConnectId,
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record CreateConnectCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public class EcliptixProtocolSystemActor : ReceiveActor
{
    private readonly ConcurrentDictionary<uint, IActorRef> _connectActorRefs = new();
    private readonly ILogger<EcliptixProtocolSystemActor> _logger;

    public EcliptixProtocolSystemActor(ILogger<EcliptixProtocolSystemActor> logger)
    {
        _logger = logger;
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectCommand>(HandleBeginAppDeviceEphemeralConnectCommand);
        ReceiveAsync<DecryptCipherPayloadActorCommand>(HandleDecryptCipherPayloadCommand);
        ReceiveAsync<EncryptPayloadActorCommand>(HandleEncryptCipherPayloadCommand);
        ReceiveAsync<CreateConnectCommand>(HandleCreateConnectCommand);
    }

    private async Task HandleBeginAppDeviceEphemeralConnectCommand(BeginAppDeviceEphemeralConnectCommand command)
    {
        uint connectId = command.UniqueConnectId;
        PubKeyExchange peerPubKeyExchange = command.PubKeyExchange;
        PubKeyExchangeState exchangeType = command.PubKeyExchange.State;

        _logger.LogInformation($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {connectId}");

        CreateConnectCommand createConnectCommand = new(connectId, peerPubKeyExchange);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> result =
            await CreateConnectActorAndDeriveSecret(createConnectCommand);

        Sender.Tell(result);
    }

    private async Task<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>> CreateConnectActorAndDeriveSecret(
        CreateConnectCommand command)
    {
        uint connectId = command.ConnectId;
        PubKeyExchange exchangeType = command.PubKeyExchange;

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

        DeriveSharedSecretCommand deriveSharedSecretCommand = new(connectId, exchangeType);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> deriveSharedSecretResult =
            await actorRef.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(deriveSharedSecretCommand);

        return deriveSharedSecretResult;
    }

    private async Task HandleCreateConnectCommand(CreateConnectCommand command)
    {
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> result =
            await CreateConnectActorAndDeriveSecret(command);
        Sender.Tell(result);
    }

    private async Task HandleEncryptCipherPayloadCommand(EncryptPayloadActorCommand actorCommand)
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

    private async Task HandleDecryptCipherPayloadCommand(DecryptCipherPayloadActorCommand actorCommand)
    {
        uint connectId = actorCommand.ConnectId;

        if (_connectActorRefs.TryGetValue(connectId, out IActorRef? actorRef))
        {
            Result<byte[], EcliptixProtocolFailure> result =
                await actorRef.Ask<Result<byte[], EcliptixProtocolFailure>>(actorCommand);
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
        _logger.LogInformation("MainShieldPro actor '{ActorPath}' is up and running.", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build(ILogger<EcliptixProtocolSystemActor> logger)
    {
        return Props.Create(() => new EcliptixProtocolSystemActor(logger));
    }
}