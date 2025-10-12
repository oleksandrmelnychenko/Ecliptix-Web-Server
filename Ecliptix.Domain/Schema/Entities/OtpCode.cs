
namespace Ecliptix.Domain.Schema.Entities;

public class OtpCodeEntity : EntityBase
{
    public long VerificationFlowId { get; set; }
    public string OtpValue { get; set; } = string.Empty;
    public string OtpSalt { get; set; } = string.Empty;
    public string Status { get; set; } = "active";
    public DateTime ExpiresAt { get; set; }
    public short AttemptCount { get; set; } = 0;
    public DateTime? VerifiedAt { get; set; }

    public virtual VerificationFlowEntity VerificationFlow { get; set; } = null!;

    public virtual ICollection<FailedOtpAttemptEntity> FailedAttempts { get; set; } = new List<FailedOtpAttemptEntity>();
}