
namespace Ecliptix.Domain.Schema.Entities;

public class MobileDeviceEntity : EntityBase
{
    public long MobileNumberId { get; set; }
    public long DeviceId { get; set; }
    public string? RelationshipType { get; set; } = "primary";
    public bool IsActive { get; set; } = true;
    public DateTime? LastUsedAt { get; set; }

    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual DeviceEntity Device { get; set; } = null!;
}