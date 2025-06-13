namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record RequestResendOtpResult
{
    public string Outcome { get; init; } = string.Empty;
}