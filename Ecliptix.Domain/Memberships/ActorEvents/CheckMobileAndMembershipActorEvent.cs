namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CheckMobileAndMembershipActorEvent(
    string MobileNumber,
    string? RegionCode,
    Guid AppDeviceId);