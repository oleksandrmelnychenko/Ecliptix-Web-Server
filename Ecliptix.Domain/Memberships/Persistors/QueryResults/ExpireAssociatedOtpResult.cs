namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record ExpireAssociatedOtpResult
{
    public string Outcome { get; init; } = string.Empty;
    public string? ErrorMessage { get; init; }
}
