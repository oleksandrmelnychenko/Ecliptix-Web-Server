using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record GetAccountsByMembershipIdEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
