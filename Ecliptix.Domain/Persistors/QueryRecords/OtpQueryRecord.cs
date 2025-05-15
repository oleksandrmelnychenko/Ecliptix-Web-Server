using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Persistors.QueryRecords;

public class OtpQueryRecord
{
    public Guid SessionIdentifier { get; init; }
    public Guid PhoneNumberIdentifier { get; init; }
    public string OtpHash { get; init; } = string.Empty;
    public string OtpSalt { get; init; } = string.Empty;
    public DateTime ExpiresAt { get; init; }
    public VerificationSessionStatus Status { get; init; }
    public bool IsActive { get; set; }
}
