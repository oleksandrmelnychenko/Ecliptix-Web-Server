namespace Ecliptix.Domain.Schema.Entities;

public class AccountEntity : EntityBase
{
    public Guid MembershipId { get; set; }
    public Guid MobileNumberId { get; set; }

    public byte[]? SecureKey { get; set; }
    public byte[]? MaskingKey { get; set; }
    public int CredentialsVersion { get; set; } = 1;

    public string Status { get; set; } = "inactive";
    public string? CreationStatus { get; set; }
    
    public virtual MembershipEntity Membership { get; set; } = null!;
    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual ICollection<MobileDeviceEntity> MobileDevices { get; set; } = new List<MobileDeviceEntity>();
    public virtual ICollection<LoginAttemptEntity> LoginAttempts { get; set; } = new List<LoginAttemptEntity>();
}