using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CheckMobileNumberAvailabilityActorEvent(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
