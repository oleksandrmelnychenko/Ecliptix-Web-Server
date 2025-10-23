namespace Ecliptix.Domain.Schema.Entities;

public class MembershipEntity : EntityBase
{
    public Guid MobileNumberId { get; set; }
    public Guid AppDeviceId { get; set; }
    public Guid? VerificationFlowId { get; set; }

    public string Status { get; set; } = "inactive";
    public string? CreationStatus { get; set; }

    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual DeviceEntity AppDevice { get; set; } = null!;
    public virtual VerificationFlowEntity? VerificationFlow { get; set; }
    public virtual ICollection<LoginAttemptEntity> LoginAttempts { get; set; } = new List<LoginAttemptEntity>();
    public virtual ICollection<MasterKeyShareEntity> MasterKeyShares { get; set; } = new List<MasterKeyShareEntity>();
    public virtual ICollection<AccountEntity> Accounts { get; set; } = new List<AccountEntity>();
    public virtual ICollection<DeviceContextEntity> DeviceContexts { get; set; } = new List<DeviceContextEntity>();
    public virtual ICollection<VerificationLogEntity> VerificationLogs { get; set; } = new List<VerificationLogEntity>();
}
