using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record UpdateVerificationFlowStatusActorEvent(
    Guid FlowIdentifier,
    VerificationFlowStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
