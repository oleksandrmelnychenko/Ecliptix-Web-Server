using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Protobuf.AppDeviceServices;
using Grpc.Core;

namespace Ecliptix.Core.Services;

public abstract class AppDeviceServiceBase(IEcliptixActorRegistry actorRegistry)
    : AppDeviceServiceActions.AppDeviceServiceActionsBase
{
    protected readonly IActorRef AppDevicePersistorActor = actorRegistry.Get<AppDevicePersistorActor>();
    protected readonly IActorRef ProtocolActor = actorRegistry.Get<EcliptixProtocolSystemActor>();
}