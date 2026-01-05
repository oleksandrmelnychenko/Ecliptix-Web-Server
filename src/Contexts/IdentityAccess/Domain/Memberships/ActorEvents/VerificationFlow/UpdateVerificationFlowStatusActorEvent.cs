using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record UpdateVerificationFlowStatusActorEvent(
    Guid FlowIdentifier,
    VerificationFlowStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
