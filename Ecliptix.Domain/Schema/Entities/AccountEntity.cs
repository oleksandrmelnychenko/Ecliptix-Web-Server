using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Schema.Entities;

public class AccountEntity : EntityBase
{
    public Guid MembershipId { get; set; }

    public AccountType AccountType { get; set; } = AccountType.Personal;
    public string AccountName { get; set; } = string.Empty;
    public byte[]? SecureKey { get; set; }
    public byte[]? MaskingKey { get; set; }
    public int CredentialsVersion { get; set; } = 1;
    public AccountStatus Status { get; set; } = AccountStatus.Inactive;
    public bool IsDefaultAccount { get; set; } = false;
    public string? PreferredLanguage { get; set; }
    public string? TimeZoneId { get; set; }
    public string? CountryCode { get; set; }
    public string? DataResidencyRegion { get; set; }

    public DateTimeOffset? LastAccessedAt { get; set; }

    public virtual MembershipEntity Membership { get; set; } = null!;
    public virtual ICollection<LoginAttemptEntity> LoginAttempts { get; set; } = new List<LoginAttemptEntity>();
    public virtual ICollection<LogoutAuditEntity> LogoutAudits { get; set; } = new List<LogoutAuditEntity>();
}
