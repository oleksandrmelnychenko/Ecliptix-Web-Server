namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;

internal record CreateOtpResult
{
    public Guid OtpUniqueId { get; init; }
    public string Outcome { get; init; } = string.Empty;
}
