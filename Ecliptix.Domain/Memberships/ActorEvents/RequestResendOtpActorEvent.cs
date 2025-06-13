namespace Ecliptix.Domain.Memberships.ActorEvents;

public record RequestResendOtpActorEvent(
    Guid FlowUniqueId
);