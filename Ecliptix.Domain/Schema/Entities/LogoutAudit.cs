namespace Ecliptix.Domain.Schema.Entities;

public class LogoutAuditEntity : EntityBase
{
    public Guid AccountUniqueId { get; set; }

    public uint ConnectId { get; set; }

    public LogoutReason Reason { get; set; } = LogoutReason.UserInitiated;

    public DateTime LoggedOutAt { get; set; } = DateTime.UtcNow;

    public virtual MembershipEntity Membership { get; set; } = null!;
}
