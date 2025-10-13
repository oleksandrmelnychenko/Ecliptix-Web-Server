namespace Ecliptix.Domain.Account.ActorEvents;

public record EnsureMobileNumberActorEvent(string MobileNumber, string? RegionCode, Guid AppDeviceIdentifier);