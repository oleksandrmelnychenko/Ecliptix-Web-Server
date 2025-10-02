namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record UpdateVerificationFlowStatusResult
{
    public int RowsAffected { get; init; }
    public string Outcome { get; init; } = string.Empty;
    public string? ErrorMessage { get; init; }
}
