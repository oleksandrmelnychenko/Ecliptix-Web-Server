namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal class VerifyPhoneForSecretKeyRecoveryResult
{
    public Guid PhoneNumberUniqueId { get; set; }
    public string Outcome { get; set; } = string.Empty;
    public bool Success { get; set; }
}