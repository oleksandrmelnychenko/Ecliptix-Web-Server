namespace Ecliptix.Domain.Schema.Entities;

public class LogoutAudit : EntityBase
{
    public Guid MembershipUniqueId { get; set; }

    public uint ConnectId { get; set; }

    public LogoutReason Reason { get; set; } = LogoutReason.UserInitiated;

    public DateTime LoggedOutAt { get; set; } = DateTime.UtcNow;

    public virtual Membership Membership { get; set; } = null!;
}
