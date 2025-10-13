namespace Ecliptix.Domain.Account.ActorEvents;

public record CheckExistingAccountActorEvent(
    Guid MobileNumberId);