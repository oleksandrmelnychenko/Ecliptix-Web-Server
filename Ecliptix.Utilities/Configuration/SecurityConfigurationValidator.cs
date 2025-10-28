using Microsoft.Extensions.Options;

namespace Ecliptix.Utilities.Configuration;

public sealed class SecurityConfigurationValidator : IValidateOptions<SecurityConfiguration>
{
    public ValidateOptionsResult Validate(string? name, SecurityConfiguration options)
    {
        List<string> errors = [];

        ValidateMembershipActorSettings(options.MembershipActor, errors);
        ValidateVerificationFlowActorSettings(options.VerificationFlowActor, errors);
        ValidateVerificationFlowPersistorSettings(options.VerificationFlowPersistor, errors);
        ValidateMembershipPersistorSettings(options.MembershipPersistor, errors);

        return errors.Count > 0
            ? ValidateOptionsResult.Fail(errors)
            : ValidateOptionsResult.Success;
    }

    private static void ValidateMembershipActorSettings(MembershipActorSettings settings, List<string> errors)
    {
        if (settings.PendingSignInTimeoutMinutes <= 0)
        {
            errors.Add($"{nameof(settings.PendingSignInTimeoutMinutes)} must be greater than 0");
        }

        if (settings.PendingPasswordRecoveryTimeoutMinutes <= 0)
        {
            errors.Add($"{nameof(settings.PendingPasswordRecoveryTimeoutMinutes)} must be greater than 0");
        }

        if (settings.CleanupIntervalMinutes <= 0)
        {
            errors.Add($"{nameof(settings.CleanupIntervalMinutes)} must be greater than 0");
        }

        if (settings.PasswordRecoveryCleanupIntervalMinutes <= 0)
        {
            errors.Add($"{nameof(settings.PasswordRecoveryCleanupIntervalMinutes)} must be greater than 0");
        }

        if (settings.SnapshotInterval <= 0)
        {
            errors.Add($"{nameof(settings.SnapshotInterval)} must be greater than 0");
        }

        if (settings.CleanupIntervalMinutes >= settings.PendingSignInTimeoutMinutes)
        {
            errors.Add(
                $"{nameof(settings.CleanupIntervalMinutes)} ({settings.CleanupIntervalMinutes}) must be less than {nameof(settings.PendingSignInTimeoutMinutes)} ({settings.PendingSignInTimeoutMinutes})");
        }

        if (settings.PasswordRecoveryCleanupIntervalMinutes >= settings.PendingPasswordRecoveryTimeoutMinutes)
        {
            errors.Add(
                $"{nameof(settings.PasswordRecoveryCleanupIntervalMinutes)} ({settings.PasswordRecoveryCleanupIntervalMinutes}) must be less than {nameof(settings.PendingPasswordRecoveryTimeoutMinutes)} ({settings.PendingPasswordRecoveryTimeoutMinutes})");
        }
    }

    private static void ValidateVerificationFlowActorSettings(VerificationFlowActorSettings settings,
        List<string> errors)
    {
        if (settings.SnapshotInterval <= 0)
        {
            errors.Add($"{nameof(settings.SnapshotInterval)} must be greater than 0");
        }

        if (settings.SessionValidityCheckTimeoutSeconds <= 0)
        {
            errors.Add($"{nameof(settings.SessionValidityCheckTimeoutSeconds)} must be greater than 0");
        }

        if (settings.ActorTerminationMinTimeoutSeconds <= 0)
        {
            errors.Add($"{nameof(settings.ActorTerminationMinTimeoutSeconds)} must be greater than 0");
        }

        if (settings.CircuitBreakerWithinTimeRangeMinutes <= 0)
        {
            errors.Add($"{nameof(settings.CircuitBreakerWithinTimeRangeMinutes)} must be greater than 0");
        }
    }

    private static void ValidateVerificationFlowPersistorSettings(VerificationFlowPersistorSettings settings,
        List<string> errors)
    {
        if (settings.FlowExpirationMinutes <= 0)
        {
            errors.Add($"{nameof(settings.FlowExpirationMinutes)} must be greater than 0");
        }

        if (settings.RateLimitLookbackHours <= 0)
        {
            errors.Add($"{nameof(settings.RateLimitLookbackHours)} must be greater than 0");
        }

        if (settings.MaxFlowsPerHourPerMobile <= 0)
        {
            errors.Add($"{nameof(settings.MaxFlowsPerHourPerMobile)} must be greater than 0");
        }

        if (settings.MaxFlowsPerHourPerDevice <= 0)
        {
            errors.Add($"{nameof(settings.MaxFlowsPerHourPerDevice)} must be greater than 0");
        }

        if (settings.PasswordRecoveryLookbackHours <= 0)
        {
            errors.Add($"{nameof(settings.PasswordRecoveryLookbackHours)} must be greater than 0");
        }
    }

    private static void ValidateMembershipPersistorSettings(MembershipPersistorSettings settings, List<string> errors)
    {
        if (settings.LoginLockoutDurationMinutes <= 0)
        {
            errors.Add($"{nameof(settings.LoginLockoutDurationMinutes)} must be greater than 0");
        }

        if (settings.MaxLoginAttemptsInPeriod <= 0)
        {
            errors.Add($"{nameof(settings.MaxLoginAttemptsInPeriod)} must be greater than 0");
        }

        if (settings.FailedLoginLookbackMinutes <= 0)
        {
            errors.Add($"{nameof(settings.FailedLoginLookbackMinutes)} must be greater than 0");
        }

        if (settings.DeviceContextExpirationDays <= 0)
        {
            errors.Add($"{nameof(settings.DeviceContextExpirationDays)} must be greater than 0");
        }

        if (settings.MembershipCreationWindowHours <= 0)
        {
            errors.Add($"{nameof(settings.MembershipCreationWindowHours)} must be greater than 0");
        }

        if (settings.MaxMembershipCreationAttempts <= 0)
        {
            errors.Add($"{nameof(settings.MaxMembershipCreationAttempts)} must be greater than 0");
        }

        if (settings.PasswordRecoveryValidationWindowMinutes <= 0)
        {
            errors.Add($"{nameof(settings.PasswordRecoveryValidationWindowMinutes)} must be greater than 0");
        }

        if (settings.LoginLockoutDurationMinutes <= settings.FailedLoginLookbackMinutes)
        {
            errors.Add(
                $"{nameof(settings.LoginLockoutDurationMinutes)} ({settings.LoginLockoutDurationMinutes}) should be greater than {nameof(settings.FailedLoginLookbackMinutes)} ({settings.FailedLoginLookbackMinutes}) to prevent immediate retries");
        }
    }
}
