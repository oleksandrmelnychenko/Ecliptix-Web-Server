namespace Ecliptix.Domain.Schema.Entities;

public class VerificationFlowEntity : EntityBase
{
    public Guid AccountId { get; set; }
    public Guid AppDeviceId { get; set; }
    public Guid MobileNumberId { get; set; }

    public string Status { get; set; } = "pending";
    public string Purpose { get; set; } = "unspecified";
    public DateTime ExpiresAt { get; set; }
    public short OtpCount { get; set; } = 0;
    public long? ConnectionId { get; set; }

    public virtual AccountEntity Account { get; set; } = null!;
    public virtual DeviceEntity Device { get; set; } = null!;
    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual ICollection<OtpCodeEntity> OtpCodes { get; set; } = new List<OtpCodeEntity>();
}