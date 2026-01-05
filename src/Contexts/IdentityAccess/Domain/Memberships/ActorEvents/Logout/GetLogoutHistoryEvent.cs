using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Logout;

public record GetLogoutHistoryEvent(
    Guid MembershipUniqueId,
    int Limit,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
