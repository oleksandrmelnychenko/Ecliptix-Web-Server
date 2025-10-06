using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Ecliptix.Domain.Schema.Entities;

public class FailedOtpAttempt : EntityBase
{
    public long OtpRecordId { get; set; }

    public string AttemptedValue { get; set; } = string.Empty;

    public string FailureReason { get; set; } = string.Empty;

    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;

    [ForeignKey(nameof(OtpRecordId))]
    public virtual OtpCode OtpRecord { get; set; } = null!;
}