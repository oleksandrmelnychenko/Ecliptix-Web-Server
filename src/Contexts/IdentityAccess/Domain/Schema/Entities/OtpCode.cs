using Ecliptix.IdentityAccess.Domain.Memberships;
namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class OtpCodeEntity : EntityBase
{
    public long VerificationFlowId { get; set; }

    public string OtpValue { get; set; } = string.Empty;
    public string OtpSalt { get; set; } = string.Empty;
    public OtpStatus Status { get; set; } = OtpStatus.Active;
    public short AttemptCount { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? VerifiedAt { get; set; }

    public VerificationFlowEntity VerificationFlow { get; set; } = null!;

    public List<FailedOtpAttemptEntity> FailedAttempts
    {
        get => field ??= [];
        set;
    }
}
