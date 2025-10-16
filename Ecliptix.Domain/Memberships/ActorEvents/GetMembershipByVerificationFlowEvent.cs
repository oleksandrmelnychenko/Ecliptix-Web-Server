using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record GetMembershipByVerificationFlowEvent(
    Guid VerificationFlowId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
