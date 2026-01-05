using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record GetDefaultAccountIdEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
