namespace Ecliptix.Domain.Memberships.ActorEvents;

public record VerifyMobileForSecretKeyRecoveryActorEvent(
    string MobileNumber, 
    string? RegionCode);