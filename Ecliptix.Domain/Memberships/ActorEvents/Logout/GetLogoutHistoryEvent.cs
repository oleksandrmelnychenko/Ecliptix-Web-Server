using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Logout;

public record GetLogoutHistoryEvent(
    Guid MembershipUniqueId,
    int Limit,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
