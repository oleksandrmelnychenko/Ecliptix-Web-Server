namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record ModifyFriendRelationResult
{
    public required string Outcome { get; init; }
    public bool Success { get; init; } = true;
}

