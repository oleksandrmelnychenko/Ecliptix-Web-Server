using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record DeleteMasterKeySharesEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
