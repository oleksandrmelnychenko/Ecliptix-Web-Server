using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record CreateDefaultAccountEvent(Guid MembershipId, Guid? AccountId = null, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
