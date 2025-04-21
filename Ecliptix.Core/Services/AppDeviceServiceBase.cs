using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Actors;
using Ecliptix.Protobuf.AppDeviceServices;

namespace Ecliptix.Core.Services;

public abstract class AppDeviceServiceBase(IActorRegistry actorRegistry, ILogger<AppDeviceServices> logger)
    : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    protected readonly ILogger<AppDeviceServices> Logger = logger;
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
}