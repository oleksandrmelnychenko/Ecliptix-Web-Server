using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record RecordLogoutEvent(
    Guid MembershipUniqueId,
    uint ConnectId,
    LogoutReason Reason);
