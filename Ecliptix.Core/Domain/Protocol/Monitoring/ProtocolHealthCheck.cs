using Akka.Actor;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;

namespace Ecliptix.Core.Domain.Protocol.Monitoring;

public class ProtocolHealthCheck : IHealthCheck
{
    private readonly ActorSystem _actorSystem;

    private static long _totalDhRatchets;
    private static long _failedDhRatchets;
    private static DateTime _lastDhRatchet = DateTime.MinValue;
    private static readonly Dictionary<uint, ConnectionHealth> _connectionHealth = new();

    public ProtocolHealthCheck(ActorSystem actorSystem)
    {
        _actorSystem = actorSystem;
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (_actorSystem.WhenTerminated.IsCompleted)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("ActorSystem is terminated"));
            }

            TimeSpan timeSinceLastRatchet = DateTime.UtcNow - _lastDhRatchet;
            bool dhRatchetHealthy = timeSinceLastRatchet < TimeSpan.FromHours(1) || _lastDhRatchet == DateTime.MinValue;

            double failureRate = _totalDhRatchets > 0 
                ? (double)_failedDhRatchets / _totalDhRatchets * 100 
                : 0;

            int healthyConnections = 0;
            int unhealthyConnections = 0;
            int staleDhKeys = 0;

            lock (_connectionHealth)
            {
                foreach (ConnectionHealth conn in _connectionHealth.Values)
                {
                    if (conn.IsHealthy)
                        healthyConnections++;
                    else
                        unhealthyConnections++;

                    if (conn.HasStaleDhKey)
                        staleDhKeys++;
                }
            }

            Dictionary<string, object> data = new()
            {
                ["actor_system"] = "running",
                ["total_dh_ratchets"] = _totalDhRatchets,
                ["failed_dh_ratchets"] = _failedDhRatchets,
                ["dh_failure_rate"] = $"{failureRate:F2}%",
                ["last_dh_ratchet"] = _lastDhRatchet == DateTime.MinValue ? "never" : _lastDhRatchet.ToString("O"),
                ["time_since_last_ratchet"] = timeSinceLastRatchet.ToString(),
                ["healthy_connections"] = healthyConnections,
                ["unhealthy_connections"] = unhealthyConnections,
                ["stale_dh_keys"] = staleDhKeys
            };

            if (failureRate > 10 || unhealthyConnections > healthyConnections)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy(
                    $"Protocol system degraded - Failure rate: {failureRate:F2}%, Unhealthy connections: {unhealthyConnections}",
                    data: data));
            }

            if (failureRate > 5 || staleDhKeys > 0)
            {
                return Task.FromResult(HealthCheckResult.Degraded(
                    $"Protocol system has warnings - Failure rate: {failureRate:F2}%, Stale DH keys: {staleDhKeys}",
                    data: data));
            }

            return Task.FromResult(HealthCheckResult.Healthy(
                $"Protocol system healthy - {healthyConnections} active connections",
                data: data));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Health check failed");
            return Task.FromResult(HealthCheckResult.Unhealthy("Health check exception", ex));
        }
    }

    public static void RecordDhRatchet(uint connectId, bool success)
    {
        Interlocked.Increment(ref _totalDhRatchets);

        if (!success)
        {
            Interlocked.Increment(ref _failedDhRatchets);
        }
        else
        {
            _lastDhRatchet = DateTime.UtcNow;
        }

        lock (_connectionHealth)
        {
            if (!_connectionHealth.TryGetValue(connectId, out ConnectionHealth? health))
            {
                health = new ConnectionHealth { ConnectId = connectId };
                _connectionHealth[connectId] = health;
            }

            health.LastDhRatchet = DateTime.UtcNow;
            health.TotalDhRatchets++;

            if (!success)
                health.FailedDhRatchets++;
        }
    }

    public static void RecordConnectionState(uint connectId, bool isHealthy, bool hasStaleDhKey = false)
    {
        lock (_connectionHealth)
        {
            if (!_connectionHealth.TryGetValue(connectId, out ConnectionHealth? health))
            {
                health = new ConnectionHealth { ConnectId = connectId };
                _connectionHealth[connectId] = health;
            }

            health.IsHealthy = isHealthy;
            health.HasStaleDhKey = hasStaleDhKey;
            health.LastUpdate = DateTime.UtcNow;
        }
    }

    public static void RemoveConnection(uint connectId)
    {
        lock (_connectionHealth)
        {
            _connectionHealth.Remove(connectId);
        }
    }

    private class ConnectionHealth
    {
        public uint ConnectId { get; set; }
        public bool IsHealthy { get; set; } = true;
        public bool HasStaleDhKey { get; set; }
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
        public DateTime LastDhRatchet { get; set; } = DateTime.MinValue;
        public long TotalDhRatchets { get; set; }
        public long FailedDhRatchets { get; set; }
    }
}