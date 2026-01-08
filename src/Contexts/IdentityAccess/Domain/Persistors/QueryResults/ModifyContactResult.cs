namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;

internal record ModifyContactResult
{
    public required string Outcome { get; init; }
    public bool Success { get; init; } = true;
}
