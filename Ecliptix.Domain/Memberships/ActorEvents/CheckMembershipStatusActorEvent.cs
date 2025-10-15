using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CheckMembershipStatusActorEvent(
    Guid MobileNumberId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
