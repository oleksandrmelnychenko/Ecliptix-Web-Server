namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class StatusChangeEntity : EntityBase
{
    public string EntityType { get; set; } = string.Empty;
    public Guid EntityId { get; set; }
    public string PropertyName { get; set; } = string.Empty;
    public string? FromValue { get; set; }
    public string? ToValue { get; set; }
    public DateTimeOffset ChangedAt { get; set; }

    public Guid? MembershipId { get; set; }
    public Guid? AccountId { get; set; }
    public Guid? DeviceId { get; set; }

    public string? Source { get; set; }
    public string? Reason { get; set; }
    public string? CorrelationId { get; set; }
    public string? Metadata { get; set; }
}
