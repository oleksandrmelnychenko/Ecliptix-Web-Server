using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetLogoutByDeviceEvent(
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
