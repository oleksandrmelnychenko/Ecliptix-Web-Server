using Ecliptix.Domain.DbConnectionFactory;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Serilog;

namespace Ecliptix.Core.Domain.Protocol.Monitoring;

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
            System.Diagnostics.Stopwatch stopwatch = System.Diagnostics.Stopwatch.StartNew();

            using System.Data.IDbConnection connection = await _connectionFactory.CreateOpenConnectionAsync();

            using System.Data.IDbCommand command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            command.CommandTimeout = 10;

            object? result = command.ExecuteScalar();

            stopwatch.Stop();

            long responseTime = stopwatch.ElapsedMilliseconds;

            Dictionary<string, object> data = new Dictionary<string, object>
            {
                ["database"] = connection.Database,
                ["server"] = connection.ConnectionString.Split(';').FirstOrDefault(s => s.StartsWith("Server="))?.Split('=')[1] ?? "unknown",
                ["response_time_ms"] = responseTime,
                ["connection_state"] = connection.State.ToString()
            };

            if (responseTime > 5000)
            {
                return HealthCheckResult.Unhealthy(
                    $"Database response time too slow: {responseTime}ms",
                    data: data);
            }

            if (responseTime > 2000)
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

            return HealthCheckResult.Unhealthy("Database connection timeout", ex);
        }
        catch (Exception ex)
        {

            return HealthCheckResult.Unhealthy("Database connection failed", ex);
        }
    }
}