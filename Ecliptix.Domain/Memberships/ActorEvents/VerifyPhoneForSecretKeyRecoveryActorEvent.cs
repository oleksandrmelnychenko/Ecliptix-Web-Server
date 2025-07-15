namespace Ecliptix.Domain.Memberships.ActorEvents;

public record VerifyPhoneForSecretKeyRecoveryActorEvent(
    string PhoneNumber, 
    string? RegionCode);