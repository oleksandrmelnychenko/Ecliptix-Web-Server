using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;

public record ProcessAndRespondToPubKeyExchangeCommand(PubKeyExchange PubKeyExchange);

public record ProcessAndRespondToPubKeyExchangeReply(PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private readonly uint _connectId;

    private EcliptixProtocolSystem _ecliptixProtocolSystem;

    public EcliptixProtocolConnectActor(uint connectId)
    {
        _connectId = connectId;
        Become(Ready);
    }

    private void Ready()
    {
        ReceiveAsync<ProcessAndRespondToPubKeyExchangeCommand>(HandleProcessAndRespondToPubKeyExchangeCommand);
    }

    private async Task HandleProcessAndRespondToPubKeyExchangeCommand(ProcessAndRespondToPubKeyExchangeCommand arg)
    {
        Result<EcliptixSystemIdentityKeys, ShieldFailure> systemIdentityKeysResult =
            EcliptixSystemIdentityKeys.Create(10);

        EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys = systemIdentityKeysResult.Unwrap();

        ShieldSessionManager shieldSessionManager = ShieldSessionManager.Create();
        _ecliptixProtocolSystem = new EcliptixProtocolSystem(ecliptixSystemIdentityKeys, shieldSessionManager);
        (uint SessionId, PubKeyExchange ResponseMessage) t =
            await _ecliptixProtocolSystem.ProcessAndRespondToPubKeyExchangeAsync(arg.PubKeyExchange);
        
        Sender.Tell(new ProcessAndRespondToPubKeyExchangeReply(t.ResponseMessage));
    }

    public static Props Build(uint connectId) =>
        Props.Create(() => new EcliptixProtocolConnectActor(connectId));
}