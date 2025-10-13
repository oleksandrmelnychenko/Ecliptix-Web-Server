namespace Ecliptix.Domain.Account.Persistors.QueryResults;

public record InsertMasterKeySharesResult
{
    public required bool Success { get; init; }
    public string? Message { get; init; }
}
