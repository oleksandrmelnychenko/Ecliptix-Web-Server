using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record FriendshipStatusQueryRecord
{
    public required MembershipRelationStatus? Status { get; init; }
    public required long? InitiatorAccountId { get; init; }
    public DateTimeOffset? Since { get; init; }
}
