using Ecliptix.IdentityAccess.Domain.Schema.Entities;
using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record GetLogoutByDeviceQuery(
    Guid DeviceId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetLogoutHistoryQuery(
    Guid MembershipUniqueId,
    int Limit,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMostRecentLogoutQuery(
    Guid MembershipUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RecordLogoutCommand(
    Guid MembershipUniqueId,
    Guid? AccountId,
    Guid DeviceId,
    LogoutReason Reason,
    string? IpAddress = null,
    string? Platform = null,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
