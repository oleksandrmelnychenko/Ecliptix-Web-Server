using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.AppDevices.Events;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.AppDevice;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services;

public class AppDeviceServices(IActorRegistry actorRegistry)
    : AppDeviceServiceBase(actorRegistry)
{
    public override async Task<PubKeyExchange> EstablishAppDeviceEphemeralConnect(PubKeyExchange request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        BeginAppDeviceEphemeralConnectActorEvent actorEvent = new(request, connectId);

        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> deriveSharedSecretReply =
            await ProtocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                actorEvent,
                context.CancellationToken);

        if (deriveSharedSecretReply.IsOk) return deriveSharedSecretReply.Unwrap().PubKeyExchange;
        throw GrpcFailureException.FromDomainFailure(deriveSharedSecretReply.UnwrapErr());
    }

    public override async Task<CipherPayload> RegisterDeviceAppIfNotExist(
        CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);
        
        DecryptCipherPayloadActorEvent decryptEvent = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            request
        );

        ForwardToConnectActorEvent decryptForwarder = new(connectId, decryptEvent);

        Result<byte[], EcliptixProtocolFailure> decryptResult = await ProtocolActor
            .Ask<Result<byte[], EcliptixProtocolFailure>>(decryptForwarder, context.CancellationToken);

        if (decryptResult.IsErr) throw GrpcFailureException.FromDomainFailure(decryptResult.UnwrapErr());

        AppDevice appDevice = Helpers.ParseFromBytes<AppDevice>(decryptResult.Unwrap());
        Result<AppDeviceRegisteredStateReply, AppDeviceFailure> persistorResult = await AppDevicePersistorActor
            .Ask<Result<AppDeviceRegisteredStateReply, AppDeviceFailure>>(
                new RegisterAppDeviceIfNotExistActorEvent(appDevice),
                context.CancellationToken
            );

        if (persistorResult.IsErr) throw GrpcFailureException.FromDomainFailure(persistorResult.UnwrapErr());

        AppDeviceRegisteredStateReply reply = persistorResult.Unwrap();

        EncryptPayloadActorEvent encryptCommand = new(PubKeyExchangeType.DataCenterEphemeralConnect,
            reply.ToByteArray()
        );

        ForwardToConnectActorEvent encryptForwarder = new(connectId, encryptCommand);
        Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await ProtocolActor
            .Ask<Result<CipherPayload, EcliptixProtocolFailure>>(encryptForwarder, context.CancellationToken);

        if (encryptResult.IsOk) return encryptResult.Unwrap();

        throw GrpcFailureException.FromDomainFailure(encryptResult.UnwrapErr());
    }
}