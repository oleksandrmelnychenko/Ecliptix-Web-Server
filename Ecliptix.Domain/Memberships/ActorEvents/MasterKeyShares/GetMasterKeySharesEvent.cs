using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;

public record GetMasterKeySharesEvent(Guid AccountUniqueId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
