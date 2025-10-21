using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetLogoutHistoryEvent(
    Guid MembershipUniqueId,
    int Limit,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
