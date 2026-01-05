using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record QueryFlowStatusByConnectionIdActorEvent(
    uint ConnectionId,
    CancellationToken CancellationToken) : ICancellableActorEvent;
