using System.Collections.Concurrent;
using Akka.Actor;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;

public record DecryptCipherPayloadCommand(
    uint ConnectId,
    PubKeyExchangeType PubKeyExchangeType,
    CipherPayload CipherPayload);

public record EncryptCipherPayloadCommand(
    uint ConnectId,
    PubKeyExchangeType PubKeyExchangeType,
    byte[] Payload);

public record CreateConnectCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public record CipherPayloadReply(CipherPayload CipherPayload);

public class EcliptixProtocolSystemActor : ReceiveActor
{
    private readonly ILogger<EcliptixProtocolSystemActor> _logger;
    private readonly ConcurrentDictionary<uint, IActorRef> _connectActorRefs = new();

    public EcliptixProtocolSystemActor(ILogger<EcliptixProtocolSystemActor> logger)
    {
        _logger = logger;
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectCommand>(HandleBeginAppDeviceEphemeralConnectCommand);
        ReceiveAsync<DecryptCipherPayloadCommand>(HandleDecryptCipherPayloadCommand);
        ReceiveAsync<EncryptCipherPayloadCommand>(HandleEncryptCipherPayloadCommand);
        ReceiveAsync<CreateConnectCommand>(HandleCreateConnectCommand);
    }

    private async Task HandleBeginAppDeviceEphemeralConnectCommand(BeginAppDeviceEphemeralConnectCommand command)
    {
        uint connectId = command.UniqueConnectId;
        PubKeyExchange peerPubKeyExchange = command.PubKeyExchange;
        PubKeyExchangeState exchangeType = command.PubKeyExchange.State;

        _logger.LogInformation($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {connectId}");

        CreateConnectCommand createConnectCommand = new(connectId, peerPubKeyExchange);
        Result<DeriveSharedSecretReply, ShieldFailure> result =
            await CreateConnectActorAndDeriveSecret(createConnectCommand);

        Sender.Tell(result);
    }

    private async Task<Result<DeriveSharedSecretReply, ShieldFailure>> CreateConnectActorAndDeriveSecret(
        CreateConnectCommand command)
    {
        uint connectId = command.ConnectId;
        PubKeyExchange exchangeType = command.PubKeyExchange;

        Result<IActorRef, ShieldFailure> actorCreationalResult = Result<IActorRef, ShieldFailure>.Try(() =>
        {
            IActorRef actorRef = Context.ActorOf(
                EcliptixProtocolConnectActor.Build(),
                $"connect-{connectId}");
            return actorRef;
        }, err => ShieldFailure.ActorNotCreated($"Failed to create actor for connectId: {connectId}", err));

        if (actorCreationalResult.IsErr)
        {
            return Result<DeriveSharedSecretReply, ShieldFailure>.Err(actorCreationalResult.UnwrapErr());
        }

        IActorRef actorRef = actorCreationalResult.Unwrap();
        _connectActorRefs.TryAdd(connectId, actorRef);

        DeriveSharedSecretCommand deriveSharedSecretCommand = new(connectId, exchangeType);
        Result<DeriveSharedSecretReply, ShieldFailure> deriveSharedSecretResult =
            await actorRef.Ask<Result<DeriveSharedSecretReply, ShieldFailure>>(deriveSharedSecretCommand);

        return deriveSharedSecretResult;
    }
    
    private async Task HandleCreateConnectCommand(CreateConnectCommand command)
    {
        Result<DeriveSharedSecretReply, ShieldFailure> result = await CreateConnectActorAndDeriveSecret(command);
        Sender.Tell(result);
    }
    
    private async Task HandleEncryptCipherPayloadCommand(EncryptCipherPayloadCommand command)
    {
        uint connectId = command.ConnectId;

        if (_connectActorRefs.TryGetValue(connectId, out IActorRef? actorRef))
        {
            Result<CipherPayload, ShieldFailure> result = await actorRef.Ask<Result<CipherPayload, ShieldFailure>>(command);
            Sender.Tell(result);
        }
        else
        {
            Sender.Tell(Result<byte[], ShieldFailure>.Err(
                ShieldFailure.ActorRefNotFound($"Connect actor with Id:{connectId} not found")));
        }
    }

    private async Task HandleDecryptCipherPayloadCommand(DecryptCipherPayloadCommand command)
    {
        uint connectId = command.ConnectId;

        if (_connectActorRefs.TryGetValue(connectId, out IActorRef? actorRef))
        {
            Result<byte[], ShieldFailure> result = await actorRef.Ask<Result<byte[], ShieldFailure>>(command);
            Sender.Tell(result);
        }
        else
        {
            Sender.Tell(Result<byte[], ShieldFailure>.Err(
                ShieldFailure.ActorRefNotFound($"Connect actor with Id:{connectId} not found")));
        }
    }

    protected override void PreStart()
    {
        _logger.LogInformation("MainShieldPro actor '{ActorPath}' is up and running.", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build(ILogger<EcliptixProtocolSystemActor> logger)
        => Props.Create(() => new EcliptixProtocolSystemActor(logger));
}