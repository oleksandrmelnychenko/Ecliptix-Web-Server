namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal class VerifyMobileForSecretKeyRecoveryResult
{
    public Guid MobileNumberUniqueId { get; set; }
    public string Outcome { get; set; } = string.Empty;
    public bool Success { get; set; }
}