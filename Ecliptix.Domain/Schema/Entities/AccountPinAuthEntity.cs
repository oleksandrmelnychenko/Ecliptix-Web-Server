namespace Ecliptix.Domain.Schema.Entities;

public class AccountPinAuthEntity : EntityBase
{
    public Guid AccountId { get; set; }
    public Guid? DeviceId { get; set; }

    public byte[] SecureKey { get; set; } = null!;
    public byte[] MaskingKey { get; set; } = null!;
    public int CredentialsVersion { get; set; } = 1;

    public bool IsPrimary { get; set; } = false;
    public bool IsEnabled { get; set; } = true;
    public bool IsDeviceSpecific { get; set; } = false;
    public int PinLength { get; set; } = 6;

    public DateTimeOffset? LastUsedAt { get; set; }
    public int FailedAttempts { get; set; } = 0;
    public DateTimeOffset? LockedUntil { get; set; }

    public virtual AccountEntity Account { get; set; } = null!;
    public virtual DeviceEntity? Device { get; set; }
}
