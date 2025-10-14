namespace Ecliptix.Domain.Schema.Entities;

public class LogoutAuditEntity : EntityBase
{
    public Guid MembershipUniqueId { get; set; }
    public Guid? AccountId { get; set; }
    public Guid? DeviceId { get; set; }

    public LogoutReason Reason { get; set; } = LogoutReason.UserInitiated;
    public string? IpAddress { get; set; }
    public string? Platform { get; set; }

    public DateTimeOffset LoggedOutAt { get; set; } = DateTimeOffset.UtcNow;

    public virtual MembershipEntity Membership { get; set; } = null!;
    public virtual AccountEntity? Account { get; set; }
    public virtual DeviceEntity? Device { get; set; }
}
