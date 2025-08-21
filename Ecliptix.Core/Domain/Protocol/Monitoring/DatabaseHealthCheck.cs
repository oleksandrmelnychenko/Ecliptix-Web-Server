using Ecliptix.Domain.DbConnectionFactory;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;

namespace Ecliptix.Core.Domain.Protocol.Monitoring;

/// <summary>
/// Health check for database connectivity and performance
/// </summary>
public class DatabaseHealthCheck : IHealthCheck
{
    private readonly IDbConnectionFactory _connectionFactory;
    
    public DatabaseHealthCheck(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            using var connection = await _connectionFactory.CreateOpenConnectionAsync();
            
            // Test basic connectivity with a simple query
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            command.CommandTimeout = 10;
            
            var result = command.ExecuteScalar();
            
            stopwatch.Stop();
            
            var responseTime = stopwatch.ElapsedMilliseconds;
            
            var data = new Dictionary<string, object>
            {
                ["database"] = connection.Database,
                ["server"] = connection.ConnectionString.Split(';').FirstOrDefault(s => s.StartsWith("Server="))?.Split('=')[1] ?? "unknown",
                ["response_time_ms"] = responseTime,
                ["connection_state"] = connection.State.ToString()
            };

            // Check response time thresholds
            if (responseTime > 5000) // 5 seconds
            {
                return HealthCheckResult.Unhealthy(
                    $"Database response time too slow: {responseTime}ms",
                    data: data);
            }
            
            if (responseTime > 2000) // 2 seconds
            {
                return HealthCheckResult.Degraded(
                    $"Database response time degraded: {responseTime}ms",
                    data: data);
            }

            return HealthCheckResult.Healthy(
                $"Database healthy - Response time: {responseTime}ms",
                data: data);
        }
        catch (TimeoutException ex)
        {
            Log.Warning(ex, "Database health check timed out");
            return HealthCheckResult.Unhealthy("Database connection timeout", ex);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Database health check failed");
            return HealthCheckResult.Unhealthy("Database connection failed", ex);
        }
    }
}