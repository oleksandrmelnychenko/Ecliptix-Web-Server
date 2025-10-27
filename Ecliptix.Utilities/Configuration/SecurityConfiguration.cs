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

    public MembershipActorSettings MembershipActor { get; set; } = new();

    public VerificationFlowActorSettings VerificationFlowActor { get; set; } = new();

    public VerificationFlowPersistorSettings VerificationFlowPersistor { get; set; } = new();

    public MembershipPersistorSettings MembershipPersistor { get; set; } = new();
}

public sealed class VerificationFlowTimeouts
{
    public int SessionTimeoutSeconds { get; set; } = 60;

    public int OtpUpdateIntervalSeconds { get; set; } = 1;

    public int OtpExpirationSeconds { get; set; } = 30;

    public int ResendCooldownBufferSeconds { get; set; } = 5;

    public int CheckExistingMembershipTimeoutSeconds { get; set; } = 10;

    public int MembershipCreationTimeoutSeconds { get; set; } = 20;

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
    public TimeSpan CheckExistingMembershipTimeout => TimeSpan.FromSeconds(CheckExistingMembershipTimeoutSeconds);
    public TimeSpan MembershipCreationTimeout => TimeSpan.FromSeconds(MembershipCreationTimeoutSeconds);
    public TimeSpan ResendOtpCheckTimeout => TimeSpan.FromSeconds(ResendOtpCheckTimeoutSeconds);
    public TimeSpan CreateOtpTimeout => TimeSpan.FromSeconds(CreateOtpTimeoutSeconds);
    public TimeSpan UpdateOtpStatusTimeout => TimeSpan.FromSeconds(UpdateOtpStatusTimeoutSeconds);
    public TimeSpan ChannelWriteTimeout => TimeSpan.FromSeconds(ChannelWriteTimeoutSeconds);
    public TimeSpan FallbackCleanupDelay => TimeSpan.FromSeconds(FallbackCleanupDelaySeconds);
}
