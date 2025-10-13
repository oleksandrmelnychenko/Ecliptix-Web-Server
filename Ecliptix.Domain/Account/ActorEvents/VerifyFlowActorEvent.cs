namespace Ecliptix.Domain.Memberships.ActorEvents;

public record VerifyFlowActorEvent(
    uint ConnectId,
    string OneTimePassword,
    string CultureName
);