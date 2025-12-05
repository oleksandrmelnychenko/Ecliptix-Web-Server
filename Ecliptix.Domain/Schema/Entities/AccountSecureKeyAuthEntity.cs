namespace Ecliptix.Domain.Schema.Entities;

public class AccountSecureKeyAuthEntity : EntityBase
{
    public Guid AccountId { get; set; }

    public byte[] SecureKey { get; set; } = null!;
    public byte[] MaskingKey { get; set; } = null!;
    public int CredentialsVersion { get; set; } = 1;

    public bool IsPrimary { get; set; }
    public bool IsEnabled { get; set; } = true;

    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }

    public AccountEntity Account { get; set; } = null!;
}
