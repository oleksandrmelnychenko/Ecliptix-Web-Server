using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record UpdateMembershipVerificationFlowEvent(
    Guid VerificationFlowId,
    string Purpose,
    string FlowStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
