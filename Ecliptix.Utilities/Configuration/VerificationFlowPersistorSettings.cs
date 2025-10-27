namespace Ecliptix.Utilities.Configuration;

public sealed class VerificationFlowPersistorSettings
{
    public int FlowExpirationMinutes { get; set; } = 15;
    public int RateLimitLookbackHours { get; set; } = 1;
    public int MaxFlowsPerHourPerMobile { get; set; } = 30;
    public int MaxFlowsPerHourPerDevice { get; set; } = 10;
    public int PasswordRecoveryLookbackHours { get; set; } = 1;

    public TimeSpan FlowExpiration => TimeSpan.FromMinutes(FlowExpirationMinutes);
    public TimeSpan RateLimitLookback => TimeSpan.FromHours(RateLimitLookbackHours);
    public TimeSpan PasswordRecoveryLookback => TimeSpan.FromHours(PasswordRecoveryLookbackHours);
}
