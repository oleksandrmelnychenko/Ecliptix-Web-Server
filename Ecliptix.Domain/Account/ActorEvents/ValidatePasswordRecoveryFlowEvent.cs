namespace Ecliptix.Domain.Memberships.ActorEvents;

public record ValidatePasswordRecoveryFlowEvent(Guid MembershipIdentifier);

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);
