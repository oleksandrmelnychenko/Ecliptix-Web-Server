using System.ComponentModel.DataAnnotations.Schema;

namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class FailedOtpAttemptEntity : EntityBase
{
    public long OtpCodeId { get; set; }

    public string AttemptedValue { get; set; } = string.Empty;
    public string FailureReason { get; set; } = string.Empty;

    public DateTimeOffset AttemptedAt { get; set; } = DateTimeOffset.UtcNow;

    [ForeignKey(nameof(OtpCodeId))]
    public OtpCodeEntity OtpCode { get; set; } = null!;
}
