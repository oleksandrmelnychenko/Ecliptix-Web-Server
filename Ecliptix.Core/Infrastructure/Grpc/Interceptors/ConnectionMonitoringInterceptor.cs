using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

/// <summary>
/// Connection monitoring interceptor that tracks active connections, connection health,
/// and provides connection statistics while integrating with existing actor lifecycle.
/// </summary>
public class ConnectionMonitoringInterceptor : Interceptor
{
    private readonly ILogger<ConnectionMonitoringInterceptor> _logger;
    private static readonly ConcurrentDictionary<uint, ConnectionInfo> ActiveConnections = new();
    private static readonly Meter ConnectionMeter = new("Ecliptix.Connections");
    
    // Metrics
    private static readonly Counter<int> ConnectionsEstablished = ConnectionMeter.CreateCounter<int>(
        "connections_established_total", 
        description: "Total number of connections established");
        
    private static readonly Counter<int> ConnectionsClosed = ConnectionMeter.CreateCounter<int>(
        "connections_closed_total", 
        description: "Total number of connections closed");
        
    private static readonly Gauge<int> ActiveConnectionsCount = ConnectionMeter.CreateGauge<int>(
        "active_connections_current", 
        description: "Current number of active connections");

    public ConnectionMonitoringInterceptor(ILogger<ConnectionMonitoringInterceptor> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        // Update active connections gauge periodically
        _ = Task.Run(async () =>
        {
            while (true)
            {
                ActiveConnectionsCount.Record(ActiveConnections.Count);
                await Task.Delay(TimeSpan.FromSeconds(10));
            }
        });
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var connectId = ExtractConnectId(context);
        if (connectId.HasValue)
        {
            TrackConnection(connectId.Value, context);
            
            // Set up cleanup on completion
            context.CancellationToken.Register(() => 
            {
                CleanupConnection(connectId.Value, "Request cancelled");
            });
        }

        try
        {
            var response = await continuation(request, context);
            
            if (connectId.HasValue)
            {
                UpdateConnectionActivity(connectId.Value);
            }
            
            return response;
        }
        catch (Exception ex)
        {
            if (connectId.HasValue)
            {
                UpdateConnectionError(connectId.Value, ex);
            }
            throw;
        }
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        var connectId = ExtractConnectId(context);
        if (connectId.HasValue)
        {
            TrackConnection(connectId.Value, context, isStreaming: true);
            
            context.CancellationToken.Register(() => 
            {
                CleanupConnection(connectId.Value, "Stream cancelled");
            });
        }

        try
        {
            await continuation(request, responseStream, context);
            
            if (connectId.HasValue)
            {
                CleanupConnection(connectId.Value, "Stream completed");
            }
        }
        catch (Exception ex)
        {
            if (connectId.HasValue)
            {
                UpdateConnectionError(connectId.Value, ex);
                CleanupConnection(connectId.Value, $"Stream error: {ex.Message}");
            }
            throw;
        }
    }

    private static uint? ExtractConnectId(ServerCallContext context)
    {
        try
        {
            // ConnectId should already be validated and stored in UserState by RequestMetaDataInterceptor
            if (context.UserState.TryGetValue("UniqueConnectId", out var connectIdObj) && 
                connectIdObj is uint connectId)
            {
                return connectId;
            }
            
            return null;
        }
        catch
        {
            return null;
        }
    }

    private void TrackConnection(uint connectId, ServerCallContext context, bool isStreaming = false)
    {
        var clientHash = GetPrivacySafeClientHash(context);
        var userAgent = SanitizeUserAgent(context.GetHttpContext().Request.Headers.UserAgent.ToString());
        var method = context.Method;

        var connectionInfo = ActiveConnections.AddOrUpdate(connectId, 
            _ => {
                ConnectionsEstablished.Add(1);
                _logger.LogDebug("New connection tracked: {ConnectId} - Method: {Method}", 
                    connectId, method);
                
                return new ConnectionInfo
                {
                    ConnectId = connectId,
                    ClientHash = clientHash, // Use hash instead of IP
                    UserAgent = userAgent,
                    FirstSeen = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow,
                    RequestCount = 1,
                    IsStreaming = isStreaming,
                    CurrentMethod = method
                };
            },
            (_, existing) => {
                existing.LastActivity = DateTime.UtcNow;
                existing.RequestCount++;
                existing.IsStreaming = isStreaming;
                existing.CurrentMethod = method;
                return existing;
            });

        // Log connection activity (rate limited)
        if (connectionInfo.RequestCount % 10 == 0) // Log every 10 requests to avoid spam
        {
            _logger.LogInformation("Connection {ConnectId} active: {RequestCount} requests over {Duration:mm\\:ss}", 
                connectId, connectionInfo.RequestCount, DateTime.UtcNow - connectionInfo.FirstSeen);
        }
    }

    private void UpdateConnectionActivity(uint connectId)
    {
        if (ActiveConnections.TryGetValue(connectId, out var info))
        {
            info.LastActivity = DateTime.UtcNow;
            info.LastError = null; // Clear any previous errors on successful request
        }
    }

    private void UpdateConnectionError(uint connectId, Exception error)
    {
        if (ActiveConnections.TryGetValue(connectId, out var info))
        {
            info.LastError = error.Message;
            info.ErrorCount++;
            
            _logger.LogWarning("Connection {ConnectId} error #{ErrorCount}: {Error}", 
                connectId, info.ErrorCount, error.Message);
        }
    }

    private void CleanupConnection(uint connectId, string reason)
    {
        if (ActiveConnections.TryRemove(connectId, out var info))
        {
            ConnectionsClosed.Add(1);
            var duration = DateTime.UtcNow - info.FirstSeen;
            
            _logger.LogInformation("Connection {ConnectId} closed after {Duration:mm\\:ss} - {RequestCount} requests, {ErrorCount} errors - Reason: {Reason}", 
                connectId, duration, info.RequestCount, info.ErrorCount, reason);
        }
    }

    /// <summary>
    /// Creates a privacy-safe client identifier hash
    /// </summary>
    private static string GetPrivacySafeClientHash(ServerCallContext context)
    {
        try
        {
            var clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = context.GetHttpContext().Request.Headers.UserAgent.ToString();
            var combined = $"{clientIp}:{userAgent}";
            
            // Create a simple hash for tracking without storing actual IP
            return Math.Abs(combined.GetHashCode()).ToString("X8");
        }
        catch
        {
            return "unknown";
        }
    }

    /// <summary>
    /// Sanitizes user agent string
    /// </summary>
    private static string SanitizeUserAgent(string userAgent)
    {
        if (string.IsNullOrEmpty(userAgent) || userAgent.Length > 200)
            return "sanitized";
            
        return userAgent.Split(' ')[0]; // Take only the first part
    }

    /// <summary>
    /// Gets current connection statistics for monitoring/health check endpoints
    /// </summary>
    public static ConnectionStatistics GetConnectionStatistics()
    {
        var connections = ActiveConnections.Values.ToList();
        var now = DateTime.UtcNow;
        
        return new ConnectionStatistics
        {
            ActiveConnectionCount = connections.Count,
            TotalRequestCount = connections.Sum(c => c.RequestCount),
            AverageConnectionDuration = connections.Any() 
                ? TimeSpan.FromTicks((long)connections.Average(c => (now - c.FirstSeen).Ticks))
                : TimeSpan.Zero,
            StreamingConnectionCount = connections.Count(c => c.IsStreaming),
            ConnectionsWithErrors = connections.Count(c => c.ErrorCount > 0),
            OldestConnection = connections.Any() 
                ? connections.Min(c => c.FirstSeen)
                : (DateTime?)null
        };
    }
}

/// <summary>
/// Information about an active connection
/// </summary>
internal class ConnectionInfo
{
    public uint ConnectId { get; set; }
    public string ClientHash { get; set; } = string.Empty; // Privacy-safe hash instead of IP
    public string UserAgent { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; }
    public DateTime LastActivity { get; set; }
    public int RequestCount { get; set; }
    public int ErrorCount { get; set; }
    public bool IsStreaming { get; set; }
    public string CurrentMethod { get; set; } = string.Empty;
    public string? LastError { get; set; }
}

/// <summary>
/// Connection statistics for monitoring
/// </summary>
public class ConnectionStatistics
{
    public int ActiveConnectionCount { get; set; }
    public int TotalRequestCount { get; set; }
    public TimeSpan AverageConnectionDuration { get; set; }
    public int StreamingConnectionCount { get; set; }
    public int ConnectionsWithErrors { get; set; }
    public DateTime? OldestConnection { get; set; }
}