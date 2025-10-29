using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record QueryFlowStatusByConnectionIdActorEvent(
    uint ConnectionId,
    CancellationToken CancellationToken) : ICancellableActorEvent;
