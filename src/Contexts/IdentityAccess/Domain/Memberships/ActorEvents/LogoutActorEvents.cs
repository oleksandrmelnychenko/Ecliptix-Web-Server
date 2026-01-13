using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record GetLogoutByDeviceEvent(
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetLogoutHistoryEvent(
    Guid MembershipUniqueId,
    int Limit,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMostRecentLogoutEvent(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RecordLogoutEvent(
    Guid MembershipUniqueId,
    Guid? AccountId,
    Guid DeviceId,
    LogoutReason Reason,
    string? IpAddress = null,
    string? Platform = null,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
