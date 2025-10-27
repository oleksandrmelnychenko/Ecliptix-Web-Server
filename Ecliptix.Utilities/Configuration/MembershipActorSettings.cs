namespace Ecliptix.Utilities.Configuration;

public sealed class MembershipActorSettings
{
    public int PendingSignInTimeoutMinutes { get; set; } = 10;
    public int PendingPasswordRecoveryTimeoutMinutes { get; set; } = 10;
    public int CleanupIntervalMinutes { get; set; } = 5;
    public int PasswordRecoveryCleanupIntervalMinutes { get; set; } = 2;
    public int SnapshotInterval { get; set; } = 100;

    public TimeSpan PendingSignInTimeout => TimeSpan.FromMinutes(PendingSignInTimeoutMinutes);
    public TimeSpan PendingPasswordRecoveryTimeout => TimeSpan.FromMinutes(PendingPasswordRecoveryTimeoutMinutes);
    public TimeSpan CleanupInterval => TimeSpan.FromMinutes(CleanupIntervalMinutes);
    public TimeSpan PasswordRecoveryCleanupInterval => TimeSpan.FromMinutes(PasswordRecoveryCleanupIntervalMinutes);
}
