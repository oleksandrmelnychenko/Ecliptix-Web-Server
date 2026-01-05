using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MobileNumber;

public record CheckMobileNumberAvailabilityActorEvent(
    Guid MobileNumberId,
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
