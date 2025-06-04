namespace Ecliptix.Domain.Memberships.Events;

public record EnsurePhoneNumberActorEvent(string PhoneNumber, string? RegionCode);