namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record UpdateOtpStatusResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
}