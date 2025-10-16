using System.Threading;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record ValidatePasswordRecoveryFlowEvent(Guid MembershipIdentifier, CancellationToken CancellationToken = default)
    : ICancellableActorEvent;

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);
