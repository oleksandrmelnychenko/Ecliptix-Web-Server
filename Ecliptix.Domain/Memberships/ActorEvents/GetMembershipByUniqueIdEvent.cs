using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetMembershipByUniqueIdEvent(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
