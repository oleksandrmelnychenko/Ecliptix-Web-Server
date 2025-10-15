using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetMasterKeySharesEvent(Guid MembershipUniqueId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
