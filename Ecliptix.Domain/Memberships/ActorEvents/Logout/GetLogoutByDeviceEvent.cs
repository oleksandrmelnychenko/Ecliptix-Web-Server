using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Logout;

public record GetLogoutByDeviceEvent(
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
