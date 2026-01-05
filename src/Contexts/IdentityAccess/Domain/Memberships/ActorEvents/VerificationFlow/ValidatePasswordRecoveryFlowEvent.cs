using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record ValidatePasswordRecoveryFlowEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;
