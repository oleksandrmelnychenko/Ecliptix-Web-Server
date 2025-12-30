using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record GetAccountsByMembershipIdEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
