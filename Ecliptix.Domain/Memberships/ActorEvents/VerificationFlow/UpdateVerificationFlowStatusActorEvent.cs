using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record UpdateVerificationFlowStatusActorEvent(
    Guid FlowIdentifier,
    VerificationFlowStatus Status,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
