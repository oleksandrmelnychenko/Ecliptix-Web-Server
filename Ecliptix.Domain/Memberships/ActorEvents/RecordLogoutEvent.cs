using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record RecordLogoutEvent(
    Guid MembershipUniqueId,
    Guid? AccountId,
    Guid DeviceId,
    LogoutReason Reason,
    string? IpAddress = null,
    string? Platform = null);
