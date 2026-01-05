using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Logout;

public record GetLogoutByDeviceEvent(
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
