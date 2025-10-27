namespace Ecliptix.Utilities.Configuration;

public sealed class MembershipPersistorSettings
{
    public int LoginLockoutDurationMinutes { get; set; } = 5;
    public int MaxLoginAttemptsInPeriod { get; set; } = 5;
    public int FailedLoginLookbackMinutes { get; set; } = 5;
    public int DeviceContextExpirationDays { get; set; } = 30;
    public int MembershipCreationWindowHours { get; set; } = 1;
    public int MaxMembershipCreationAttempts { get; set; } = 5;
    public int PasswordRecoveryValidationWindowMinutes { get; set; } = 10;

    public TimeSpan LoginLockoutDuration => TimeSpan.FromMinutes(LoginLockoutDurationMinutes);
    public TimeSpan FailedLoginLookback => TimeSpan.FromMinutes(FailedLoginLookbackMinutes);
    public TimeSpan DeviceContextExpiration => TimeSpan.FromDays(DeviceContextExpirationDays);
    public TimeSpan MembershipCreationWindow => TimeSpan.FromHours(MembershipCreationWindowHours);
    public TimeSpan PasswordRecoveryValidationWindow => TimeSpan.FromMinutes(PasswordRecoveryValidationWindowMinutes);
}
