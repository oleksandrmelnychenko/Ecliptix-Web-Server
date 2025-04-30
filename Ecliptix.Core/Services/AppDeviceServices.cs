using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Core.Services.Utilities;
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

    public override async Task<CipherPayload> RegisterDeviceAppIfNotExist(CipherPayload request,
        ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractConnectId(context);

        DecryptCipherPayloadCommand decryptCipherPayloadCommand =
            new(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect, request);

        Result<byte[], ShieldFailure> decryptionResult =
            await ProtocolActor.Ask<Result<byte[], ShieldFailure>>(decryptCipherPayloadCommand);
        if (decryptionResult.IsOk)
        {
            AppDevice appDevice = Helpers.ParseFromBytes<AppDevice>(decryptionResult.Unwrap());
            
            
            
            
            
            
            
            
            AppDeviceRegisteredStateReply appDeviceRegisteredStateReply = new()
            {
                Status = AppDeviceRegisteredStateReply.Types.Status.SuccessNewRegistration
            };
            
            EncryptCipherPayloadCommand encryptCipherPayloadCommand =
                new(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect, appDeviceRegisteredStateReply.ToByteArray());
            
            Result<CipherPayload, ShieldFailure> encryptionResult =
                await ProtocolActor.Ask<Result<CipherPayload, ShieldFailure>>(encryptCipherPayloadCommand);

            if (encryptionResult.IsOk)
            {
                return encryptionResult.Unwrap();
            }
        }

        context.Status = ShieldFailure.ToGrpcStatus(decryptionResult.UnwrapErr());
        return new CipherPayload();
    }
}