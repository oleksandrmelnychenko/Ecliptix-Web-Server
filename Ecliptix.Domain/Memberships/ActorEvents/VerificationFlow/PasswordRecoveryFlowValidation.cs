namespace Ecliptix.Domain.Memberships.ActorEvents.VerificationFlow;

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);
