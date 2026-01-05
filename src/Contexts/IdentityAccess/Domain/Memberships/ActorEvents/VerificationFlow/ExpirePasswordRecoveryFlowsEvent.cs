using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record ExpirePasswordRecoveryFlowsEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
