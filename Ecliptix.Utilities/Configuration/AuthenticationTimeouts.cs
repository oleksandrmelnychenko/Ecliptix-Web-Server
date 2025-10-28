namespace Ecliptix.Utilities.Configuration;

public sealed class AuthenticationTimeouts
{
    public int PendingSignInTimeoutSeconds { get; set; } = 600;

    public int PendingPasswordRecoveryTimeoutSeconds { get; set; } = 600;

    public int CleanupIntervalSeconds { get; set; } = 300;

    public int PasswordRecoveryCleanupIntervalSeconds { get; set; } = 120;


    public TimeSpan PendingSignInTimeout => TimeSpan.FromSeconds(PendingSignInTimeoutSeconds);
    public TimeSpan PendingPasswordRecoveryTimeout => TimeSpan.FromSeconds(PendingPasswordRecoveryTimeoutSeconds);
    public TimeSpan CleanupInterval => TimeSpan.FromSeconds(CleanupIntervalSeconds);
    public TimeSpan PasswordRecoveryCleanupInterval => TimeSpan.FromSeconds(PasswordRecoveryCleanupIntervalSeconds);
}
