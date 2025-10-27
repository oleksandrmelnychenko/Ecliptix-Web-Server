namespace Ecliptix.Utilities.Configuration;

public sealed class VerificationFlowActorSettings
{
    public int SnapshotInterval { get; set; } = 100;
    public int SessionValidityCheckTimeoutSeconds { get; set; } = 5;
    public int ActorTerminationMinTimeoutSeconds { get; set; } = 5;
    public int CircuitBreakerWithinTimeRangeMinutes { get; set; } = 1;

    public TimeSpan SessionValidityCheckTimeout => TimeSpan.FromSeconds(SessionValidityCheckTimeoutSeconds);
    public TimeSpan ActorTerminationMinTimeout => TimeSpan.FromSeconds(ActorTerminationMinTimeoutSeconds);
    public TimeSpan CircuitBreakerWithinTimeRange => TimeSpan.FromMinutes(CircuitBreakerWithinTimeRangeMinutes);
}
