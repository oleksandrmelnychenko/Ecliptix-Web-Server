using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.MasterKeyShares;

public record GetMasterKeySharesEvent(Guid MembershipUniqueId, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
