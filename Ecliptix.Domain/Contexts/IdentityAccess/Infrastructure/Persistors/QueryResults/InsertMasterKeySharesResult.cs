namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

public record InsertMasterKeySharesResult
{
    public required bool Success { get; init; }
    public string? Message { get; init; }
}
