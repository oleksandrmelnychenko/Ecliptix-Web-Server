namespace Ecliptix.Domain.Memberships.ActorEvents;

public record UpdateOtpStatusActorEvent(Guid OtpIdentified, VerificationFlowStatus Status);