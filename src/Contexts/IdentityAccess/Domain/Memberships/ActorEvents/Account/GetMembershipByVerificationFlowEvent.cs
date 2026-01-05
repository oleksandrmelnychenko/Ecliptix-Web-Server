using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Account;

public record GetMembershipByVerificationFlowEvent(
    Guid VerificationFlowId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
