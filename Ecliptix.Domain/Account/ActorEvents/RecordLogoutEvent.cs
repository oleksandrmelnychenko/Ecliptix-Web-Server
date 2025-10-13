using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Account.ActorEvents;

public record RecordLogoutEvent(
    Guid AccountUniqueId,
    uint ConnectId,
    LogoutReason Reason);
