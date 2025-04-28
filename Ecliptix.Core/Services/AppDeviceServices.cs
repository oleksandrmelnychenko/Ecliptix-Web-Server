using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Actors;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Core.Services.Utilities;
using Ecliptix.Protobuf.AppDevice;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;
using Status = Grpc.Core.Status;

namespace Ecliptix.Core.Services;

public class AppDeviceServices(IActorRegistry actorRegistry, ILogger<AppDeviceServices> logger)
    : AppDeviceServiceBase(actorRegistry, logger)
{
    public override async Task<PubKeyExchange> EstablishAppDeviceEphemeralConnect(PubKeyExchange request,
        ServerCallContext context)
    {
        Logger.LogInformation("Received EstablishAppDeviceEphemeralConnect request with type {RequestType}",
            request.OfType);

        try
        {
           uint connectId = ServiceUtilities.ExtractUniqueConnectId(context);
            
            BeginAppDeviceEphemeralConnectCommand command = new(request, connectId);
            ProcessAndRespondToPubKeyExchangeReply response =
                await ProtocolActor.Ask<ProcessAndRespondToPubKeyExchangeReply>(
                    command,
                    context.CancellationToken);
            return response.PubKeyExchange;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public override async Task<CipherPayload> RegisterDeviceAppIfNotExist(CipherPayload request, ServerCallContext context)
    {
        uint connectId = ServiceUtilities.ExtractUniqueConnectId(context);
        
        DecryptCipherPayloadCommand cipherPayloadCommand=
            new(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect, request);
        byte[] payload = await ProtocolActor.Ask<byte[]>(cipherPayloadCommand);
        
        AppDevice appDevice = Helpers.ParseFromBytes<AppDevice>(payload);

        return new CipherPayload();
    }
}