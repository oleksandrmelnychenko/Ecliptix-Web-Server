namespace Ecliptix.Domain.Account.ActorEvents;

public record VerifyMobileForSecretKeyRecoveryActorEvent(
    string MobileNumber,
    string? RegionCode);