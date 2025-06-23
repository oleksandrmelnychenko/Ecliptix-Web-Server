using Akka.Actor;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Serilog;

namespace Ecliptix.Core.Protocol.Actors;

public record DeriveSharedSecretActorEvent(uint ConnectId, PubKeyExchange PubKeyExchange);

public record DeriveSharedSecretReply(PubKeyExchange PubKeyExchange);

public class EcliptixProtocolConnectActor : ReceiveActor
{
    private const int LocalKeyCount = 10;

    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(5);

    private readonly uint _connectId;
    private readonly EcliptixProtocolSystem _ecliptixProtocolSystem;

    public EcliptixProtocolConnectActor(uint connectId)
    {
        _connectId = connectId;

        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> identityKeysResult =
            EcliptixSystemIdentityKeys.Create(LocalKeyCount);

        if (identityKeysResult.IsErr)
            throw new ActorInitializationException(
                $"Failed to create EcliptixSystemIdentityKeys for ConnectId {_connectId}"
            );

        _ecliptixProtocolSystem = new EcliptixProtocolSystem(identityKeysResult.Unwrap());

        Become(Ready);
    }

    protected override void PreStart()
    {
        Context.SetReceiveTimeout(IdleTimeout);
        Log.Information("Session actor for ConnectId {ConnectId} started. Inactivity timeout is {Timeout}", _connectId,
            IdleTimeout);
        base.PreStart();
    }

    private void Ready()
    {
        Receive<DeriveSharedSecretActorEvent>(HandleProcessAndRespondToPubKeyExchangeCommand);
        Receive<DecryptCipherPayloadActorEvent>(HandleDecryptCipherPayloadCommand);
        Receive<EncryptPayloadActorEvent>(HandleEncryptCipherPayloadCommand);

        Receive<ReceiveTimeout>(_ => HandleIdleTimeout());
    }

    private void HandleIdleTimeout()
    {
        Log.Warning(
            "Session actor for ConnectId {ConnectId} is stopping due to inactivity. Session keys will be discarded",
            _connectId);

        Context.Stop(Self);
    }

    private void HandleEncryptCipherPayloadCommand(EncryptPayloadActorEvent actorEvent)
    {
        Result<CipherPayload, EcliptixProtocolFailure> cipherPayload =
            _ecliptixProtocolSystem.ProduceOutboundMessage(actorEvent.Payload);
        Sender.Tell(cipherPayload);
    }

    private void HandleDecryptCipherPayloadCommand(DecryptCipherPayloadActorEvent actorEvent)
    {
        Result<byte[], EcliptixProtocolFailure> payload =
            _ecliptixProtocolSystem.ProcessInboundMessage(actorEvent.CipherPayload);
        Sender.Tell(payload);
    }

    private void HandleProcessAndRespondToPubKeyExchangeCommand(DeriveSharedSecretActorEvent arg)
    {
        Result<PubKeyExchange, EcliptixProtocolFailure> pubKeyExchange =
            _ecliptixProtocolSystem.ProcessAndRespondToPubKeyExchange(arg.ConnectId, arg.PubKeyExchange);

        if (pubKeyExchange.IsOk)
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Ok(
                new DeriveSharedSecretReply(pubKeyExchange.Unwrap())));
        else
            Sender.Tell(Result<DeriveSharedSecretReply, EcliptixProtocolFailure>.Err(
                pubKeyExchange.UnwrapErr()));
    }

    public static Props Build(uint connectId)
    {
        return Props.Create(() => new EcliptixProtocolConnectActor(connectId));
    }
}