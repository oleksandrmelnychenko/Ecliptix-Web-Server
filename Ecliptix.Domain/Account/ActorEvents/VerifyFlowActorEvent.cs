namespace Ecliptix.Domain.Account.ActorEvents;

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword,
    string CultureName
);