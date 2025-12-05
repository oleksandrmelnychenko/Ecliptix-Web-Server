namespace Ecliptix.Domain.Schema.Entities;

public class DeviceEntity : EntityBase
{
    public Guid AppInstanceId { get; set; }
    public Guid DeviceId { get; set; }
    public int DeviceType { get; set; } = 1;

    public List<VerificationFlowEntity> VerificationFlows
    {
        get => field ??= [];
        set;
    }

    public List<MembershipEntity> Memberships
    {
        get => field ??= [];
        set;
    }

    public List<DeviceContextEntity> DeviceContexts
    {
        get => field ??= [];
        set;
    }
}
