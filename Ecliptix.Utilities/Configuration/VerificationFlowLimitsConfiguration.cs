namespace Ecliptix.Utilities.Configuration;

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
