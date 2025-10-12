namespace Ecliptix.Domain.Schema.Entities;

public class VerificationFlowEntity : EntityBase
{
    public long MobileNumberId { get; set; }
    public Guid AppDeviceId { get; set; }
    public string Status { get; set; } = "pending";
    public string Purpose { get; set; } = "unspecified";
    public DateTime ExpiresAt { get; set; }
    public short OtpCount { get; set; } = 0;
    public long? ConnectionId { get; set; }

    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual DeviceEntity AppDevice { get; set; } = null!;

    public virtual ICollection<OtpCodeEntity> OtpCodes { get; set; } = new List<OtpCodeEntity>();
    public virtual ICollection<MembershipEntity> Memberships { get; set; } = new List<MembershipEntity>();
}