using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;
using Ecliptix.IdentityAccess.Domain.Schema.Entities;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Logout;

public record RecordLogoutEvent(
    Guid MembershipUniqueId,
    Guid? AccountId,
    Guid DeviceId,
    LogoutReason Reason,
    string? IpAddress = null,
    string? Platform = null,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
