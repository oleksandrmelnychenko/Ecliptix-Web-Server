namespace Ecliptix.Domain.Memberships.ActorEvents;

public record CheckExistingMembershipActorEvent(
    Guid MobileNumberId);