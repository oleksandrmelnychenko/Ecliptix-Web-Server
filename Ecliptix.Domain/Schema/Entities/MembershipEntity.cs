namespace Ecliptix.Domain.Schema.Entities;

public class MembershipEntity : EntityBase
{
    public Guid MobileNumberId { get; set; }
    public Guid AppDeviceId { get; set; }
    public Guid? VerificationFlowId { get; set; } // Nullable - only set during password recovery
    public byte[]? SecureKey { get; set; }
    public byte[]? MaskingKey { get; set; }
    public int CredentialsVersion { get; set; } = 1;

    public string Status { get; set; } = "inactive";
    public string? CreationStatus { get; set; }

    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual DeviceEntity AppDevice { get; set; } = null!;
    public virtual VerificationFlowEntity? VerificationFlow { get; set; }
    public virtual ICollection<LoginAttemptEntity> LoginAttempts { get; set; } = new List<LoginAttemptEntity>();
    public virtual ICollection<MasterKeyShareEntity> MasterKeyShares { get; set; } = new List<MasterKeyShareEntity>();
    public virtual ICollection<AccountEntity> Accounts { get; set; } = new List<AccountEntity>();
    public virtual ICollection<DeviceContextEntity> DeviceContexts { get; set; } = new List<DeviceContextEntity>();
}