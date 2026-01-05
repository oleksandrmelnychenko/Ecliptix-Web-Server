namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.VerificationFlow;

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);
