using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record FriendshipStatusQueryRecord
{
    public required FriendRelationStatus? Status { get; init; }
    public required Guid? RequestedById { get; init; }
    public DateTimeOffset? Since { get; init; }
}

