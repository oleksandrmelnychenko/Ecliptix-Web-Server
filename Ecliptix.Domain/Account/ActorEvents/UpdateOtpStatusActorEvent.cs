namespace Ecliptix.Domain.Account.ActorEvents;

public record UpdateOtpStatusActorEvent(Guid OtpIdentified, VerificationFlowStatus Status);