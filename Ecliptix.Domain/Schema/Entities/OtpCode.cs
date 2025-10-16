using Ecliptix.Domain.Schema.Interfaces;
using Ecliptix.Domain.Status;

namespace Ecliptix.Domain.Schema.Entities;

public class OtpCodeEntity : EntityBase, IExpirable
{
    public long VerificationFlowId { get; set; }

    public string OtpValue { get; set; } = string.Empty;
    public string OtpSalt { get; set; } = string.Empty;
    public string Status { get; set; } = StatusCatalog.Otp.Active;
    public short AttemptCount { get; set; } = 0;

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? VerifiedAt { get; set; }

    public virtual VerificationFlowEntity VerificationFlow { get; set; } = null!;
    public virtual ICollection<FailedOtpAttemptEntity> FailedAttempts { get; set; } = new List<FailedOtpAttemptEntity>();
}
