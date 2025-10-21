using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetMostRecentLogoutEvent(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
