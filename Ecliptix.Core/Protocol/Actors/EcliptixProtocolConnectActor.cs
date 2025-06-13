using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol.Actors;

public record DeriveSharedSecretCommand(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private const int LocalKeyCount = 10;
    private readonly EcliptixProtocolSystem? _ecliptixProtocolSystem;

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
        Result<byte[], EcliptixProtocolFailure> payload =
            _ecliptixProtocolSystem!.ProcessInboundMessage(actorCommand.CipherPayload);
        Sender.Tell(payload);
    }

    private void HandleProcessAndRespondToPubKeyExchangeCommand(DeriveSharedSecretCommand arg)
    {
        Result<PubKeyExchange, EcliptixProtocolFailure> pubKeyExchange =
            _ecliptixProtocolSystem!.ProcessAndRespondToPubKeyExchange(arg.ConnectId, arg.PubKeyExchange);

        if (pubKeyExchange.IsOk)
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(
                new DeriveSharedSecretReply(pubKeyExchange.Unwrap())));
        else
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(
                pubKeyExchange.UnwrapErr()));
    }

    public static Props Build()
    {
        return Props.Create(() => new EcliptixProtocolConnectActor());
    }
}