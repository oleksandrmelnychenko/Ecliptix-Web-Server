using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Ecliptix.Domain.Schema.Entities;

public class FailedOtpAttemptEntity : EntityBase
{
    public long OtpRecordId { get; set; }

    public string AttemptedValue { get; set; } = string.Empty;
    public string FailureReason { get; set; } = string.Empty;

    public DateTimeOffset AttemptedAt { get; set; } = DateTimeOffset.UtcNow;

    // Navigation property - no virtual
    [ForeignKey(nameof(OtpRecordId))]
    public OtpCodeEntity OtpRecord { get; set; } = null!;
}
