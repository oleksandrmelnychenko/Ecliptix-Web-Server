using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Persistors;
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
        Result<DeriveSharedSecretReply, ShieldFailure> deriveSharedSecretReply =
            await ProtocolActor.Ask<Result<DeriveSharedSecretReply, ShieldFailure>>(
                command,
                context.CancellationToken);

        if (deriveSharedSecretReply.IsOk)
        {
            return deriveSharedSecretReply.Unwrap().PubKeyExchange;
        }

        context.Status = ShieldFailure.ToGrpcStatus(deriveSharedSecretReply.UnwrapErr());
        return new PubKeyExchange();
    }

    public override async Task<CipherPayload> RegisterDeviceAppIfNotExist(
        CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        Result<byte[], ShieldFailure> decryptResult = await ProtocolActor
            .Ask<Result<byte[], ShieldFailure>>(
                new DecryptCipherPayloadCommand(
                    connectId,
                    PubKeyExchangeType.AppDeviceEphemeralConnect,
                    request
                ),
                context.CancellationToken
            );

        if (!decryptResult.IsOk)
        {
            context.Status = ShieldFailure.ToGrpcStatus(decryptResult.UnwrapErr());
            return new CipherPayload();
        }

        AppDevice appDevice = Helpers.ParseFromBytes<AppDevice>(decryptResult.Unwrap());
        Result<(Guid, int), ShieldFailure> persistorResult = await AppDevicePersistorActor
            .Ask<Result<(Guid, int), ShieldFailure>>(
                new RegisterAppDeviceIfNotExistCommand(appDevice),
                context.CancellationToken
            );

        if (!persistorResult.IsOk)
        {
            context.Status = ShieldFailure.ToGrpcStatus(persistorResult.UnwrapErr());
            return new CipherPayload();
        }

        (Guid id, int status) = persistorResult.Unwrap();
        AppDeviceRegisteredStateReply.Types.Status currentStatus = status switch
        {
            0 => AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration,
            1 => AppDeviceRegisteredStateReply.Types.Status.SuccessAlreadyExists,
            _ => throw new InvalidOperationException($"Unexpected status code: {status}")
        };

        AppDeviceRegisteredStateReply reply = new()
        {
            Status = currentStatus,
            UniqueId = Helpers.GuidToByteString(id)
        };

        Result<CipherPayload, ShieldFailure> encryptResult = await ProtocolActor
            .Ask<Result<CipherPayload, ShieldFailure>>(
                new EncryptCipherPayloadCommand(
                    connectId,
                    PubKeyExchangeType.AppDeviceEphemeralConnect,
                    reply.ToByteArray()
                ),
                context.CancellationToken
            );

        if (!encryptResult.IsOk)
        {
            context.Status = ShieldFailure.ToGrpcStatus(encryptResult.UnwrapErr());
            return new CipherPayload();
        }

        return encryptResult.Unwrap();
    }
}