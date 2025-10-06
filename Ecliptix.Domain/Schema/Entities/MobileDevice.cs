
namespace Ecliptix.Domain.Schema.Entities;

public class MobileDevice : EntityBase
{
    public long MobileNumberId { get; set; }
    public long DeviceId { get; set; }
    public string? RelationshipType { get; set; } = "primary";
    public bool IsActive { get; set; } = true;
    public DateTime? LastUsedAt { get; set; }

    public virtual MobileNumber MobileNumber { get; set; } = null!;
    public virtual Device Device { get; set; } = null!;
}