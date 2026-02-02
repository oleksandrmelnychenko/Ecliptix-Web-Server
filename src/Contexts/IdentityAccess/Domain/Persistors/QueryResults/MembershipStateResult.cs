using Ecliptix.IdentityAccess.Domain.Memberships;

namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;

public sealed record MembershipStateResult(
    Guid UniqueId,
    Guid DeviceId,
    MembershipStatus Status,
    MembershipCreationStatus? CreationStatus,
    DateTimeOffset CreatedAt);
