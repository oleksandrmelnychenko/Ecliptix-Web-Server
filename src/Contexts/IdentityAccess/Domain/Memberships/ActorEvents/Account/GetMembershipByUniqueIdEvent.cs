using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record GetMembershipByUniqueIdEvent(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
