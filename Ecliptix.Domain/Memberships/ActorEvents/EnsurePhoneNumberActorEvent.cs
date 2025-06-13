namespace Ecliptix.Domain.Memberships.ActorEvents;

public record EnsurePhoneNumberActorEvent(string PhoneNumber, string? RegionCode,Guid AppDeviceIdentifier);
