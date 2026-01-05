using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MasterKeyShares;

public record DeleteMasterKeySharesEvent(Guid AccountId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
