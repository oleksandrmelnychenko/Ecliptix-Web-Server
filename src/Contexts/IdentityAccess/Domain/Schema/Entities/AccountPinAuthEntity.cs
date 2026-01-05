namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class AccountPinAuthEntity : EntityBase
{
    public Guid AccountId { get; set; }
    public Guid? DeviceId { get; set; }

    public byte[] SecureKey { get; set; } = null!;
    public byte[] MaskingKey { get; set; } = null!;
    public int CredentialsVersion { get; set; } = 1;

    public bool IsPrimary { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsDeviceSpecific { get; set; }
    public int PinLength { get; set; } = 6;

    public DateTimeOffset? LastUsedAt { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }

    public AccountEntity Account { get; set; } = null!;
    public DeviceEntity? Device { get; set; }
}
