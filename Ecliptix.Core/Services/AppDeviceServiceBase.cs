using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.Persistors;
using Ecliptix.Protobuf.AppDeviceServices;

namespace Ecliptix.Core.Services;

public abstract class AppDeviceServiceBase(IActorRegistry actorRegistry, ILogger<AppDeviceServices> logger)
    : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    protected readonly ILogger<AppDeviceServices> Logger = logger;
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
    protected readonly IActorRef AppDevicePersistorActor = actorRegistry.Get<AppDevicePersistorActor>();
}