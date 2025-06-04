namespace Ecliptix.Domain.Memberships.Events;

public record UpdateOtpStatusActorEvent(Guid OtpIdentified, VerificationFlowStatus Status);