using Ecliptix.Protobuf.AppDeviceServices;
using Ecliptix.Protobuf.PubKeyExchange;
using Grpc.Core;

namespace Ecliptix.Core.Services;

public class AppDeviceServices : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    public AppDeviceServices()
    {
    }

    public override Task<PubKeyExchange> EstablishAppDeviceEphemeralConnect(PubKeyExchange request,
        ServerCallContext context)
    {
        
        
        return base.EstablishAppDeviceEphemeralConnect(request, context);
    }
}