namespace Ecliptix.Domain.Schema.Entities;

public class VerificationFlow : EntityBase
{
    public long MobileNumberId { get; set; }
    public Guid AppDeviceId { get; set; }
    public string Status { get; set; } = "pending";
    public string Purpose { get; set; } = "unspecified";
    public DateTime ExpiresAt { get; set; }
    public short OtpCount { get; set; } = 0;
    public long? ConnectionId { get; set; }

    public virtual MobileNumber MobileNumber { get; set; } = null!;
    public virtual Device AppDevice { get; set; } = null!;

    public virtual ICollection<OtpCode> OtpCodes { get; set; } = new List<OtpCode>();
    public virtual ICollection<Membership> Memberships { get; set; } = new List<Membership>();
}