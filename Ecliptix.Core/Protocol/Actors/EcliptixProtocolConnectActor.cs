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
        Result<EcliptixSystemIdentityKeys, ShieldFailure> identityKeysResult =
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
        CipherPayload cipherPayload = _ecliptixProtocolSystem!.ProduceOutboundMessage(actorCommand.ConnectId,
            actorCommand.PubKeyExchangeType, actorCommand.Payload);
        Sender.Tell(Result<CipherPayload, ShieldFailure>.Ok(cipherPayload));
    }

    private void HandleDecryptCipherPayloadCommand(DecryptCipherPayloadActorCommand actorCommand)
    {
        byte[] payload = _ecliptixProtocolSystem!.ProcessInboundMessage(actorCommand.ConnectId,
            actorCommand.PubKeyExchangeType, actorCommand.CipherPayload);
        Sender.Tell(Result<byte[], ShieldFailure>.Ok(payload));
    }

    private void HandleProcessAndRespondToPubKeyExchangeCommand(DeriveSharedSecretCommand arg)
    {
        PubKeyExchange pubKeyExchange =
            _ecliptixProtocolSystem!.ProcessAndRespondToPubKeyExchange(arg.ConnectId, arg.PubKeyExchange);

        Sender.Tell(Result<DeriveSharedSecretReply, ShieldFailure>.Ok(
            new DeriveSharedSecretReply(pubKeyExchange)));
    }

    public static Props Build() =>
        Props.Create(() => new EcliptixProtocolConnectActor());
}