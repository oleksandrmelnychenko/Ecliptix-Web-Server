namespace Ecliptix.Domain.Account.ActorEvents;

public record ValidatePasswordRecoveryFlowEvent(Guid AccountIdentifier);

public record PasswordRecoveryFlowValidation(bool IsValid, Guid? FlowId);
