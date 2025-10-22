namespace Ecliptix.Utilities.Configuration;

public sealed class SecurityConfiguration
{
    public const string SectionName = "Security";

    public VerificationFlowTimeouts VerificationFlow { get; set; } = new();

    public CryptographicParameters Cryptography { get; set; } = new();

    public AuthenticationTimeouts Authentication { get; set; } = new();

    public OtpHashingConfiguration OtpHashing { get; set; } = new();

    public GrpcSecurityParameters GrpcSecurity { get; set; } = new();

    public VerificationFlowLimitsConfiguration VerificationFlowLimits { get; set; } = new();
}

public sealed class VerificationFlowTimeouts
{
    public int SessionTimeoutSeconds { get; set; } = 60;

    public int OtpUpdateIntervalSeconds { get; set; } = 1;

    public int OtpExpirationSeconds { get; set; } = 30;

    public int ResendCooldownBufferSeconds { get; set; } = 5;

    public int MembershipCreationTimeoutSeconds { get; set; } = 10;

    public int ResendOtpCheckTimeoutSeconds { get; set; } = 15;

    public int CreateOtpTimeoutSeconds { get; set; } = 20;

    public int UpdateOtpStatusTimeoutSeconds { get; set; } = 10;

    public int ChannelWriteTimeoutSeconds { get; set; } = 30;

    public int FallbackCleanupDelaySeconds { get; set; } = 10;

    public int MaxSmsRetries { get; set; } = 3;

    public int MaxOtpVerificationAttempts { get; set; } = 3;


    public TimeSpan SessionTimeout => TimeSpan.FromSeconds(SessionTimeoutSeconds);
    public TimeSpan OtpUpdateInterval => TimeSpan.FromSeconds(OtpUpdateIntervalSeconds);
    public TimeSpan OtpExpiration => TimeSpan.FromSeconds(OtpExpirationSeconds);
    public TimeSpan MembershipCreationTimeout => TimeSpan.FromSeconds(MembershipCreationTimeoutSeconds);
    public TimeSpan ResendOtpCheckTimeout => TimeSpan.FromSeconds(ResendOtpCheckTimeoutSeconds);
    public TimeSpan CreateOtpTimeout => TimeSpan.FromSeconds(CreateOtpTimeoutSeconds);
    public TimeSpan UpdateOtpStatusTimeout => TimeSpan.FromSeconds(UpdateOtpStatusTimeoutSeconds);
    public TimeSpan ChannelWriteTimeout => TimeSpan.FromSeconds(ChannelWriteTimeoutSeconds);
    public TimeSpan FallbackCleanupDelay => TimeSpan.FromSeconds(FallbackCleanupDelaySeconds);
}

public sealed class CryptographicParameters
{
    public int Argon2MemorySize { get; set; } = 262144;

    public int Argon2Iterations { get; set; } = 4;

    public int Argon2DegreeOfParallelism { get; set; } = 4;

    public int EnhancedKeyOutputLength { get; set; } = 64;

    public int MasterKeySize { get; set; } = 32;

    public int DefaultThreshold { get; set; } = 3;

    public int DefaultTotalShares { get; set; } = 5;

    public int AskTimeoutSeconds { get; set; } = 30;


    public TimeSpan AskTimeout => TimeSpan.FromSeconds(AskTimeoutSeconds);
}

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

public sealed class OtpHashingConfiguration
{
    public int SaltSize { get; set; } = 32;

    public int Pbkdf2Iterations { get; set; } = 100000;

    public int HashOutputLength { get; set; } = 32;
}

public sealed class GrpcSecurityParameters
{
    public int MaxTimestampDriftSeconds { get; set; } = 300;

    public TimeSpan MaxTimestampDrift => TimeSpan.FromSeconds(MaxTimestampDriftSeconds);
}

public sealed class VerificationFlowLimitsConfiguration
{
    public int MaxOtpSendsPerFlow { get; set; } = 5;
    public int MaxOtpSendsPerMobilePerHour { get; set; } = 5;
    public int OtpExhaustionCooldownMinutes { get; set; } = 60;
    public int PasswordRecoveryAttemptsPerHourPerMobile { get; set; } = 3;
    public int PasswordRecoveryAttemptsPerHourPerDevice { get; set; } = 3;
    public int VerificationFlowInitiationsPerHourPerMobile { get; set; } = 10;
    public int VerificationFlowInitiationsPerHourPerDevice { get; set; } = 15;
}
