namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record CreateOtpResult
{
    public Guid OtpUniqueId { get; init; }
    public string Outcome { get; init; } = string.Empty;
}