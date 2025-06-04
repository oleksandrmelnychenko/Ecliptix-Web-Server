namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public class OtpQueryRecord
{
    public Guid UniqueIdentifier { get; init; }
    public Guid SessionIdentifier { get; init; }
    public Guid PhoneNumberIdentifier { get; init; }
    public string OtpHash { get; init; } = string.Empty;
    public string OtpSalt { get; init; } = string.Empty;
    public DateTime ExpiresAt { get; init; }
    public VerificationFlowStatus Status { get; init; }
    public bool IsActive { get; set; }
}
