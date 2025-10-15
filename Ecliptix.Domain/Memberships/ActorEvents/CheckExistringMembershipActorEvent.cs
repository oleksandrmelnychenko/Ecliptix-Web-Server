using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CheckExistingMembershipActorEvent(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
