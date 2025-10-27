using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Account;

public record GetMembershipByVerificationFlowEvent(
    Guid VerificationFlowId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
