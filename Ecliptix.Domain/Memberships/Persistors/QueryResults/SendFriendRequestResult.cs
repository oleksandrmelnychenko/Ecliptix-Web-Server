namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record SendFriendRequestResult
{
    public required Guid RelationId { get; init; }
    public required string Outcome { get; init; }
}

