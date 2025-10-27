using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;

public record DeleteMasterKeySharesEvent(Guid MembershipId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
