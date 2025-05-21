using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Persistors.QueryRecords;

public record MembershipQueryRecord
{
    public required Guid UniqueIdentifier { get; init; }
    
    public required Membership.Types.MembershipStatus Status { get; init; }
}