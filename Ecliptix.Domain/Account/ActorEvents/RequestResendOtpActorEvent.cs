namespace Ecliptix.Domain.Account.ActorEvents;

public record RequestResendOtpActorEvent(
    Guid FlowUniqueId
);