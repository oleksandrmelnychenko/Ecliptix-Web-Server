using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Schema.Entities;

public class AccountEntity : EntityBase
{
    public Guid MembershipId { get; set; }

    public AccountType AccountType { get; set; } = AccountType.Personal;
    public AccountStatus Status { get; set; } = AccountStatus.Inactive;
    public bool IsDefaultAccount { get; set; }
    public string? PreferredLanguage { get; set; }
    public string? TimeZoneId { get; set; }
    public string? CountryCode { get; set; }
    public string? DataResidencyRegion { get; set; }

    public DateTimeOffset? LastAccessedAt { get; set; }

    public AccountProfileEntity Profile { get; set; } = null!;
    public MembershipEntity Membership { get; set; } = null!;

    public List<LoginAttemptEntity> LoginAttempts
    {
        get => field ??= [];
        set;
    }

    public List<LogoutAuditEntity> LogoutAudits
    {
        get => field ??= [];
        set;
    }

    public List<AccountSecureKeyAuthEntity> SecureKeyAuths
    {
        get => field ??= [];
        set;
    }

    public List<AccountPinAuthEntity> PinAuths
    {
        get => field ??= [];
        set;
    }

    public List<VerificationLogEntity> VerificationLogs
    {
        get => field ??= [];
        set;
    }
}
