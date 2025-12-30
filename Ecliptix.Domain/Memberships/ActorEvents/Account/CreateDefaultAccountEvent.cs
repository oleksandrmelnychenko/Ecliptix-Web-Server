using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record CreateDefaultAccountEvent(Guid MembershipId, Guid? AccountId = null, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
