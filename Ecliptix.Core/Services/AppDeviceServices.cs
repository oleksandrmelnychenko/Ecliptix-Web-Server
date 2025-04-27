using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Actors;
using Ecliptix.Core.Actors.Messages;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Core.Services.Utilities;
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
            BeginAppDeviceEphemeralConnectCommand command = new(request, ServiceUtilities.ExtractUniqueConnectId(context));
            ProcessAndRespondToPubKeyExchangeReply response =
                await ProtocolActor.Ask<ProcessAndRespondToPubKeyExchangeReply>(
                    command,
                    TimeSpan.FromSeconds(35),
                    context.CancellationToken);
            return response.PubKeyExchange;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}