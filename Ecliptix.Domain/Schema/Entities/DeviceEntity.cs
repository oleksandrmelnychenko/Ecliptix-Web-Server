using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Ecliptix.Domain.Schema.Entities;

public class DeviceEntity : EntityBase
{
    public Guid AppInstanceId { get; set; }

    public Guid DeviceId { get; set; }

    public int DeviceType { get; set; } = 1;

    public virtual ICollection<VerificationFlowEntity> VerificationFlows { get; set; } = new List<VerificationFlowEntity>();
    public virtual ICollection<MembershipEntity> Memberships { get; set; } = new List<MembershipEntity>();
    public virtual ICollection<MobileDeviceEntity> MobileDevices { get; set; } = new List<MobileDeviceEntity>();
}