namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class LoginAttemptEntity : EntityBase
{
    public Guid? MembershipUniqueId { get; set; }
    public Guid? AccountId { get; set; }
    public Guid? DeviceId { get; set; }

    public string? MobileNumber { get; set; }
    public string? Outcome { get; set; }
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public string? IpAddress { get; set; }
    public string? Platform { get; set; }

    public DateTimeOffset AttemptedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }

    public MembershipEntity? Membership { get; set; }
    public AccountEntity? Account { get; set; }
    public DeviceEntity? Device { get; set; }
}
