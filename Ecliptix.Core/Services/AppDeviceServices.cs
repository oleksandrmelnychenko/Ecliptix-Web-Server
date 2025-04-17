using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Actors;
using Ecliptix.Protobuf.AppDeviceServices;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services;

public class AppDeviceServices(IActorRegistry actorRegistry, ILogger<AppDeviceServices> logger)
    : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    private readonly IActorRef _protocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    private readonly ILogger<AppDeviceServices> _logger = logger;

    public override Task<PubKeyExchange> EstablishAppDeviceEphemeralConnect(PubKeyExchange request,
        ServerCallContext context)
    {
        
        
        return base.EstablishAppDeviceEphemeralConnect(request, context);
    }
}