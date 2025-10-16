using System.Threading;
using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.ActorEvents;

public record RecordLogoutEvent(
    Guid MembershipUniqueId,
    Guid? AccountId,
    Guid DeviceId,
    LogoutReason Reason,
    string? IpAddress = null,
    string? Platform = null,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
