using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record UpdateMembershipVerificationFlowEvent(
    Guid VerificationFlowId,
    VerificationPurpose Purpose,
    VerificationFlowStatus FlowStatus,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
