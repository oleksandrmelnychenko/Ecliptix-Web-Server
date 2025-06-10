using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol.Actors;

public record DeriveSharedSecretCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private readonly EcliptixProtocolSystem? _ecliptixProtocolSystem;

    private const int LocalKeyCount = 10;

    public EcliptixProtocolConnectActor()
    {
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> identityKeysResult =
            EcliptixSystemIdentityKeys.Create(LocalKeyCount);
        if (identityKeysResult.IsErr)
        {
            Sender.Tell(identityKeysResult.UnwrapErr());
            return;
        }

        _ecliptixProtocolSystem = new EcliptixProtocolSystem(identityKeysResult.Unwrap());

        Become(Ready);
    }

    private void Ready()
    {
        Receive<DeriveSharedSecretCommand>(HandleProcessAndRespondToPubKeyExchangeCommand);
        Receive<DecryptCipherPayloadActorCommand>(HandleDecryptCipherPayloadCommand);
        Receive<EncryptPayloadActorCommand>(HandleEncryptCipherPayloadCommand);
    }

    private void HandleEncryptCipherPayloadCommand(EncryptPayloadActorCommand actorCommand)
    {
        Result<CipherPayload, EcliptixProtocolFailure> cipherPayload =
            _ecliptixProtocolSystem!.ProduceOutboundMessage(actorCommand.Payload);
        Sender.Tell(cipherPayload);
    }

    private void HandleDecryptCipherPayloadCommand(DecryptCipherPayloadActorCommand actorCommand)
    {
        var payload = _ecliptixProtocolSystem!.ProcessInboundMessage(actorCommand.CipherPayload);
        Sender.Tell(payload);
    }

    private void HandleProcessAndRespondToPubKeyExchangeCommand(DeriveSharedSecretCommand arg)
    {
        var pubKeyExchange =
            _ecliptixProtocolSystem!.ProcessAndRespondToPubKeyExchange(arg.ConnectId, arg.PubKeyExchange);

        Sender.Tell(pubKeyExchange);
    }

    public static Props Build() =>
        Props.Create(() => new EcliptixProtocolConnectActor());
}