namespace Ecliptix.Domain.Schema.Entities;

public class MobileDeviceEntity : EntityBase
{
    public Guid AccountId { get; set; }
    public Guid DeviceId { get; set; }
    public string? RelationshipType { get; set; } = "primary";
    public bool IsActive { get; set; } = true;
    public DateTime? LastUsedAt { get; set; }

    public virtual AccountEntity Account { get; set; } = null!;
    public virtual DeviceEntity Device { get; set; } = null!;
}