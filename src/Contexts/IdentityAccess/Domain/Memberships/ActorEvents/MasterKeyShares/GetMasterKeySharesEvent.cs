using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MasterKeyShares;

public record GetMasterKeySharesEvent(Guid AccountUniqueId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
