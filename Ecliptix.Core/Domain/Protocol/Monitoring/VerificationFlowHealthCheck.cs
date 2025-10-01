using Akka.Actor;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;

namespace Ecliptix.Core.Domain.Protocol.Monitoring;

public class VerificationFlowHealthCheck : IHealthCheck
{
    private readonly IEcliptixActorRegistry _actorRegistry;

    private static long _totalVerificationAttempts;
    private static long _successfulVerifications;
    private static long _failedVerifications;
    private static long _timeoutVerifications;
    private static DateTime _lastVerificationAttempt = DateTime.MinValue;
    private static readonly Dictionary<string, FlowHealth> _activeFlows = new();

    public VerificationFlowHealthCheck(IEcliptixActorRegistry actorRegistry)
    {
        _actorRegistry = actorRegistry;
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            IActorRef verificationManagerActor = _actorRegistry.Get(ActorIds.VerificationFlowManagerActor);
            if (verificationManagerActor.IsNobody())
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("VerificationFlowManagerActor is not available"));
            }

            double successRate = _totalVerificationAttempts > 0 
                ? (double)_successfulVerifications / _totalVerificationAttempts * 100 
                : 100;

            double timeoutRate = _totalVerificationAttempts > 0 
                ? (double)_timeoutVerifications / _totalVerificationAttempts * 100 
                : 0;

            int activeFlowCount;
            int staleFlowCount = 0;

            lock (_activeFlows)
            {
                activeFlowCount = _activeFlows.Count;
                DateTime staleThreshold = DateTime.UtcNow.AddMinutes(-15);

                staleFlowCount = _activeFlows.Values.Count(f => f.StartTime < staleThreshold);
            }

            Dictionary<string, object> data = new Dictionary<string, object>
            {
                ["verification_manager_actor"] = "available",
                ["total_verification_attempts"] = _totalVerificationAttempts,
                ["successful_verifications"] = _successfulVerifications,
                ["failed_verifications"] = _failedVerifications,
                ["timeout_verifications"] = _timeoutVerifications,
                ["success_rate"] = $"{successRate:F2}%",
                ["timeout_rate"] = $"{timeoutRate:F2}%",
                ["active_flows"] = activeFlowCount,
                ["stale_flows"] = staleFlowCount,
                ["last_verification_attempt"] = _lastVerificationAttempt == DateTime.MinValue ? "never" : _lastVerificationAttempt.ToString("O")
            };

            if (successRate < 80 || timeoutRate > 20 || staleFlowCount > 10)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy(
                    $"Verification system degraded - Success rate: {successRate:F2}%, Timeout rate: {timeoutRate:F2}%, Stale flows: {staleFlowCount}",
                    data: data));
            }

            if (successRate < 90 || timeoutRate > 10 || staleFlowCount > 5)
            {
                return Task.FromResult(HealthCheckResult.Degraded(
                    $"Verification system has warnings - Success rate: {successRate:F2}%, Timeout rate: {timeoutRate:F2}%, Stale flows: {staleFlowCount}",
                    data: data));
            }

            return Task.FromResult(HealthCheckResult.Healthy(
                $"Verification system healthy - {activeFlowCount} active flows, {successRate:F2}% success rate",
                data: data));
        }
        catch (Exception ex)
        {

            return Task.FromResult(HealthCheckResult.Unhealthy("Verification health check exception", ex));
        }
    }

    public static void RecordVerificationAttempt(string flowId)
    {
        Interlocked.Increment(ref _totalVerificationAttempts);
        _lastVerificationAttempt = DateTime.UtcNow;

        lock (_activeFlows)
        {
            _activeFlows[flowId] = new FlowHealth
            {
                FlowId = flowId,
                StartTime = DateTime.UtcNow
            };
        }
    }

    public static void RecordVerificationSuccess(string flowId)
    {
        Interlocked.Increment(ref _successfulVerifications);

        lock (_activeFlows)
        {
            _activeFlows.Remove(flowId);
        }
    }

    public static void RecordVerificationFailure(string flowId)
    {
        Interlocked.Increment(ref _failedVerifications);

        lock (_activeFlows)
        {
            _activeFlows.Remove(flowId);
        }
    }

    public static void RecordVerificationTimeout(string flowId)
    {
        Interlocked.Increment(ref _timeoutVerifications);

        lock (_activeFlows)
        {
            _activeFlows.Remove(flowId);
        }
    }

    private class FlowHealth
    {
        public string FlowId { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
    }
}