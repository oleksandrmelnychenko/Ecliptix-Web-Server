
namespace Ecliptix.Domain.Schema.Entities;

public class OtpCode : EntityBase
{
    public long VerificationFlowId { get; set; }
    public string OtpValue { get; set; } = string.Empty;
    public string OtpSalt { get; set; } = string.Empty;
    public string Status { get; set; } = "active";
    public DateTime ExpiresAt { get; set; }
    public short AttemptCount { get; set; } = 0;
    public DateTime? VerifiedAt { get; set; }

    public virtual VerificationFlow VerificationFlow { get; set; } = null!;

    public virtual ICollection<FailedOtpAttempt> FailedAttempts { get; set; } = new List<FailedOtpAttempt>();
}