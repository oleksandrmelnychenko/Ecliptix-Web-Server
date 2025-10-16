using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record ExpirePasswordRecoveryFlowsEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
