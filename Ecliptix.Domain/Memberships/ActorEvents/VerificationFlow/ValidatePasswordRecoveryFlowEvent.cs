using System.Threading;
using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record ValidatePasswordRecoveryFlowEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);
