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

public class AppDeviceServices(IActorRegistry actorRegistry, ILogger<AppDeviceServices> logger)
    : AppDeviceServiceBase(actorRegistry, logger)
{
    public override async Task<PubKeyExchange> EstablishAppDeviceEphemeralConnect(PubKeyExchange request,
        ServerCallContext context)
    {
        Logger.LogInformation("Received EstablishAppDeviceEphemeralConnect request with type {RequestType}",
            request.OfType);

        uint connectId = ServiceUtilities.ExtractConnectId(context);
        BeginAppDeviceEphemeralConnectCommand command = new(request, connectId);
        Result<DeriveSharedSecretReply, EcliptixProtocolFailure> deriveSharedSecretReply =
            await ProtocolActor.Ask<Result<DeriveSharedSecretReply, EcliptixProtocolFailure>>(
                command,
                context.CancellationToken);

        if (deriveSharedSecretReply.IsOk)
        {
            return deriveSharedSecretReply.Unwrap().PubKeyExchange;
        }

        context.Status = EcliptixProtocolFailure.ToGrpcStatus(deriveSharedSecretReply.UnwrapErr());
        return new PubKeyExchange();
    }

    public override async Task<CipherPayload> RegisterDeviceAppIfNotExist(
        CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], EcliptixProtocolFailure> decryptResult = await ProtocolActor
            .Ask<Result<byte[], EcliptixProtocolFailure>>(
                new DecryptCipherPayloadActorCommand(
                    connectId,
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    request
                ),
                context.CancellationToken
            );

        if (decryptResult.IsErr)
        {
            context.Status = EcliptixProtocolFailure.ToGrpcStatus(decryptResult.UnwrapErr());
            return new CipherPayload();
        }

        AppDevice appDevice = Helpers.ParseFromBytes<AppDevice>(decryptResult.Unwrap());
        Result<(Guid, int), AppDeviceFailure> persistorResult = await AppDevicePersistorActor
            .Ask<Result<(Guid, int), AppDeviceFailure>>(
                new RegisterAppDeviceIfNotExistActorEvent(appDevice)
            );

        if (persistorResult.IsErr)
        {
            context.Status = AppDeviceFailure.ToGrpcStatus(persistorResult.UnwrapErr());
            return new CipherPayload();
        }

        (Guid id, int status) = persistorResult.Unwrap();
        AppDeviceRegisteredStateReply.Types.Status currentStatus = status switch
        {
            1 => AppDeviceRegisteredStateReply.Types.Status.SuccessAlreadyExists,
            2 => AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration, 
            0 => AppDeviceRegisteredStateReply.Types.Status.FailureInvalidRequest,
            _ => AppDeviceRegisteredStateReply.Types.Status.FailureInternalError 
        };

        AppDeviceRegisteredStateReply reply = new()
        {
            Status = currentStatus,
            UniqueId = Helpers.GuidToByteString(id)
        };

        Result<CipherPayload, EcliptixProtocolFailure> encryptResult = await ProtocolActor
            .Ask<Result<CipherPayload, EcliptixProtocolFailure>>(
                new EncryptPayloadActorCommand(
                    connectId,
                    PubKeyExchangeType.DataCenterEphemeralConnect,
                    reply.ToByteArray()
                ),
                context.CancellationToken
            );

        if (encryptResult.IsErr)
        {
            context.Status = EcliptixProtocolFailure.ToGrpcStatus(encryptResult.UnwrapErr());
            return new CipherPayload();
        }

        return encryptResult.Unwrap();
    }
}