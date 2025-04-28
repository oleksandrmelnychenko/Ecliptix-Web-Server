using Akka.Actor;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Actors;

public record ProcessAndRespondToPubKeyExchangeCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public record ProcessAndRespondToPubKeyExchangeReply(PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private EcliptixProtocolSystem _ecliptixProtocolSystem;

    public EcliptixProtocolConnectActor()
    {
        Become(Ready);
    }

    private void Ready()
    {
        Receive<ProcessAndRespondToPubKeyExchangeCommand>(HandleProcessAndRespondToPubKeyExchangeCommand);
        Receive<DecryptCipherPayloadCommand>(HandleDecryptCipherPayloadCommand);
    }

    private void HandleDecryptCipherPayloadCommand(DecryptCipherPayloadCommand command)
    {
        byte[] payload = _ecliptixProtocolSystem.ProcessInboundMessageAsync(command.UniqueConnectId,
            command.PubKeyExchangeType, command.CipherPayload);
        Sender.Tell(payload);
    }

    private void HandleProcessAndRespondToPubKeyExchangeCommand(ProcessAndRespondToPubKeyExchangeCommand arg)
    {
        Result<EcliptixSystemIdentityKeys, ShieldFailure> systemIdentityKeysResult =
            EcliptixSystemIdentityKeys.Create(10);

        EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys = systemIdentityKeysResult.Unwrap();

        _ecliptixProtocolSystem = new EcliptixProtocolSystem(ecliptixSystemIdentityKeys);

        PubKeyExchange pubKeyExchange =
            _ecliptixProtocolSystem.ProcessAndRespondToPubKeyExchangeAsync(arg.ConnectId, arg.PubKeyExchange);

        Sender.Tell(new ProcessAndRespondToPubKeyExchangeReply(pubKeyExchange));
    }

    public static Props Build() =>
        Props.Create(() => new EcliptixProtocolConnectActor());
}