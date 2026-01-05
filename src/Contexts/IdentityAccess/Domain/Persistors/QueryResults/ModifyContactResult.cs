namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryResults;

internal record ModifyContactResult
{
    public required string Outcome { get; init; }
    public bool Success { get; init; } = true;
}
