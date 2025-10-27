using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Schema.Interfaces;

namespace Ecliptix.Domain.Schema.Entities;

public class OtpCodeEntity : EntityBase, IExpirable
{
    public long VerificationFlowId { get; set; }

    public string OtpValue { get; set; } = string.Empty;
    public string OtpSalt { get; set; } = string.Empty;
    public OtpStatus Status { get; set; } = OtpStatus.Active;
    public short AttemptCount { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? VerifiedAt { get; set; }

    public virtual VerificationFlowEntity VerificationFlow { get; set; } = null!;
    public virtual ICollection<FailedOtpAttemptEntity> FailedAttempts { get; set; } = new List<FailedOtpAttemptEntity>();
}
