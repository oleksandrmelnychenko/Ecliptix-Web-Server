using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record GetDefaultAccountIdEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
