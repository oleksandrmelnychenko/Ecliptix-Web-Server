using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.MobileNumber;

public record CheckMobileNumberAvailabilityActorEvent(
    Guid MobileNumberId,
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
