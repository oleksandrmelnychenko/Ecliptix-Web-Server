namespace Ecliptix.Utilities.Configuration;

public sealed class GrpcSecurityParameters
{
    public int MaxTimestampDriftSeconds { get; set; } = 300;

    public TimeSpan MaxTimestampDrift => TimeSpan.FromSeconds(MaxTimestampDriftSeconds);
}
