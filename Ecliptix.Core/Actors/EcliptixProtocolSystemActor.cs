using Akka.Actor;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;

public record DecryptCipherPayloadCommand(uint UniqueConnectId, PubKeyExchangeType PubKeyExchangeType, CipherPayload CipherPayload);

public record CipherPayloadReply(CipherPayload CipherPayload);

public class EcliptixProtocolSystemActor
    : ReceiveActor
{
    private readonly ILogger<EcliptixProtocolSystemActor> _logger;

    private readonly IActorRef _ecliptixProtocolConnectsManagerActor;

    public EcliptixProtocolSystemActor(
        IActorRef ecliptixProtocolConnectsManagerActor,
        ILogger<EcliptixProtocolSystemActor> logger)
    {
        _ecliptixProtocolConnectsManagerActor = ecliptixProtocolConnectsManagerActor;
        _logger = logger;
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<BeginAppDeviceEphemeralConnectCommand>(HandleBeginAppDeviceEphemeralConnectCommand);
        ReceiveAsync<DecryptCipherPayloadCommand>(HandleDecryptCipherPayloadCommand);
    }

    private async Task HandleDecryptCipherPayloadCommand(DecryptCipherPayloadCommand command)
    {
        byte[] result = await _ecliptixProtocolConnectsManagerActor
            .Ask<byte[]>(command);
        
        Sender.Tell(result);
    }

    private async Task
        HandleBeginAppDeviceEphemeralConnectCommand(BeginAppDeviceEphemeralConnectCommand command)
    {
        uint connectId = command.UniqueConnectId;
        PubKeyExchange peerPubKeyExchange = command.PubKeyExchange;
        PubKeyExchangeState exchangeType = command.PubKeyExchange.State;

        _logger.LogInformation($"[ShieldPro] Beginning exchange {exchangeType}, generated Session ID: {connectId}");

        CreateConnectCommand createConnectCommand = new(connectId, peerPubKeyExchange);
        ProcessAndRespondToPubKeyExchangeReply? result =
            await _ecliptixProtocolConnectsManagerActor.Ask<ProcessAndRespondToPubKeyExchangeReply>(
                createConnectCommand);

        Sender.Tell(result);
    }

    protected override void PostStop()
    {
        base.PostStop();
    }

    protected override void PreStart()
    {
        _logger.LogInformation("MainShieldPro actor '{ActorPath}' is up and running.", Context.Self.Path);
        base.PreStart();
    }

    public static Props Build(IActorRef ecliptixProtocolConnectionsManagerActor,
        ILogger<EcliptixProtocolSystemActor> logger)
        => Props.Create(() =>
            new EcliptixProtocolSystemActor(ecliptixProtocolConnectionsManagerActor, logger));
}