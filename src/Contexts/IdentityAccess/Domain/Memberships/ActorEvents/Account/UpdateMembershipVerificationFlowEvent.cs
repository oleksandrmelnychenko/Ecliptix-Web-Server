using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record UpdateMembershipVerificationFlowEvent(
    Guid VerificationFlowId,
    VerificationPurpose Purpose,
    VerificationFlowStatus FlowStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
