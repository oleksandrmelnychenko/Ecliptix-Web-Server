using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record MembershipQueryRecord
{
    public required Guid UniqueIdentifier { get; init; }
    public required Membership.Types.ActivityStatus ActivityStatus { get; init; }
    public Membership.Types.CreationStatus CreationStatus { get; init; }
}