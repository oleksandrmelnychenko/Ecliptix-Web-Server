namespace Ecliptix.Domain.Schema.Entities;

public class DeviceEntity : EntityBase
{
    public Guid AppInstanceId { get; set; }
    public Guid DeviceId { get; set; }
    public int DeviceType { get; set; } = 1;

    public virtual ICollection<MobileDeviceEntity> MobileDevices { get; set; } = new List<MobileDeviceEntity>();
    public virtual ICollection<VerificationFlowEntity> VerificationFlows { get; set; } = new List<VerificationFlowEntity>();
}