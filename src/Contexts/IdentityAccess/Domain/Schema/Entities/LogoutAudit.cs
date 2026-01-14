namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class LogoutAuditEntity : EntityBase
{
    public Guid MembershipId { get; set; }
    public Guid? AccountId { get; set; }
    public Guid? DeviceId { get; set; }

    public LogoutReason Reason { get; set; } = LogoutReason.UserInitiated;
    public string? IpAddress { get; set; }
    public string? Platform { get; set; }

    public DateTimeOffset LoggedOutAt { get; set; } = DateTimeOffset.UtcNow;

    public MembershipEntity Membership { get; set; } = null!;
    public AccountEntity? Account { get; set; }
}
