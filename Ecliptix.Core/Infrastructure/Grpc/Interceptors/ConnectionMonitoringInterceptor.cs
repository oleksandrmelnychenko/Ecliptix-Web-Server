using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class ConnectionMonitoringInterceptor : Interceptor
{
    private static readonly ConcurrentDictionary<uint, ConnectionInfo> ActiveConnections = new();
    private static readonly Meter ConnectionMeter = new(InterceptorConstants.Telemetry.ConnectionsMeter);

    private static readonly Counter<int> ConnectionsEstablished = ConnectionMeter.CreateCounter<int>(
        InterceptorConstants.Metrics.ConnectionsEstablishedTotal, 
        description: InterceptorConstants.Metrics.ConnectionsEstablishedTotalDescription);

    private static readonly Counter<int> ConnectionsClosed = ConnectionMeter.CreateCounter<int>(
        InterceptorConstants.Metrics.ConnectionsClosedTotal, 
        description: InterceptorConstants.Metrics.ConnectionsClosedTotalDescription);

    private static readonly Gauge<int> ActiveConnectionsCount = ConnectionMeter.CreateGauge<int>(
        InterceptorConstants.Metrics.ActiveConnectionsCurrent, 
        description: InterceptorConstants.Metrics.ActiveConnectionsCurrentDescription);

    public ConnectionMonitoringInterceptor()
    {

        _ = Task.Run(async () =>
        {
            while (true)
            {
                ActiveConnectionsCount.Record(ActiveConnections.Count);
                await Task.Delay(TimeSpan.FromSeconds(InterceptorConstants.Thresholds.ConnectionMonitoringUpdateIntervalSeconds));
            }
        });
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        uint? connectId = ExtractConnectId(context);
        if (connectId.HasValue)
        {
            TrackConnection(connectId.Value, context);

            context.CancellationToken.Register(() => 
            {
                CleanupConnection(connectId.Value, InterceptorConstants.Connections.CloseReasons.RequestCancelled);
            });
        }

        try
        {
            TResponse response = await continuation(request, context);

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
        uint? connectId = ExtractConnectId(context);
        if (connectId.HasValue)
        {
            TrackConnection(connectId.Value, context, isStreaming: true);

            context.CancellationToken.Register(() => 
            {
                CleanupConnection(connectId.Value, InterceptorConstants.Connections.CloseReasons.StreamCancelled);
            });
        }

        try
        {
            await continuation(request, responseStream, context);

            if (connectId.HasValue)
            {
                CleanupConnection(connectId.Value, InterceptorConstants.Connections.CloseReasons.StreamCompleted);
            }
        }
        catch (Exception ex)
        {
            if (connectId.HasValue)
            {
                UpdateConnectionError(connectId.Value, ex);
                CleanupConnection(connectId.Value, string.Format(InterceptorConstants.Connections.CloseReasons.StreamError, ex.Message));
            }
            throw;
        }
    }

    private static uint? ExtractConnectId(ServerCallContext context)
    {
        try
        {
            if (context.UserState.TryGetValue(InterceptorConstants.Connections.UniqueConnectIdKey, out object? connectIdObj) && 
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
        string clientHash = GetPrivacySafeClientHash(context);
        string userAgent = SanitizeUserAgent(context.GetHttpContext().Request.Headers.UserAgent.ToString());
        string method = context.Method;

        ConnectionInfo connectionInfo = ActiveConnections.AddOrUpdate(connectId, 
            _ => {
                ConnectionsEstablished.Add(InterceptorConstants.Numbers.One);
                Log.Debug(InterceptorConstants.LogMessages.ConnectionTracked,
                    connectId, method);

                return new ConnectionInfo
                {
                    ConnectId = connectId,
                    ClientHash = clientHash,
                    UserAgent = userAgent,
                    FirstSeen = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow,
                    RequestCount = InterceptorConstants.Numbers.One,
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

        if (connectionInfo.RequestCount % InterceptorConstants.Limits.ConnectionLogFrequency == InterceptorConstants.Numbers.Zero)
        {
            Log.Information(InterceptorConstants.LogMessages.ConnectionActive,
                connectId, connectionInfo.RequestCount, DateTime.UtcNow - connectionInfo.FirstSeen);
        }
    }

    private void UpdateConnectionActivity(uint connectId)
    {
        if (ActiveConnections.TryGetValue(connectId, out ConnectionInfo? info))
        {
            info.LastActivity = DateTime.UtcNow;
            info.LastError = null; 
        }
    }

    private void UpdateConnectionError(uint connectId, Exception error)
    {
        if (ActiveConnections.TryGetValue(connectId, out ConnectionInfo? info))
        {
            info.LastError = error.Message;
            info.ErrorCount++;

            Log.Warning(InterceptorConstants.LogMessages.ConnectionError,
                connectId, info.ErrorCount, error.Message);
        }
    }

    private void CleanupConnection(uint connectId, string reason)
    {
        if (ActiveConnections.TryRemove(connectId, out ConnectionInfo? info))
        {
            ConnectionsClosed.Add(InterceptorConstants.Numbers.One);
            TimeSpan duration = DateTime.UtcNow - info.FirstSeen;

            Log.Information(InterceptorConstants.LogMessages.ConnectionClosed,
                connectId, duration, info.RequestCount, info.ErrorCount, reason);
        }
    }

    private static string GetPrivacySafeClientHash(ServerCallContext context)
    {
        try
        {
            string clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? InterceptorConstants.Connections.Unknown;
            string userAgent = context.GetHttpContext().Request.Headers.UserAgent.ToString();
            string combined = $"{clientIp}{InterceptorConstants.Characters.Colon}{userAgent}";

            return Math.Abs(combined.GetHashCode()).ToString(InterceptorConstants.Formatting.HashFormat);
        }
        catch
        {
            return InterceptorConstants.Connections.Unknown;
        }
    }

    private static string SanitizeUserAgent(string userAgent)
    {
        if (string.IsNullOrEmpty(userAgent) || userAgent.Length > InterceptorConstants.Limits.MaxUserAgentLength)
            return InterceptorConstants.Connections.Sanitized;

        return userAgent.Split(InterceptorConstants.Characters.Space)[InterceptorConstants.Numbers.FirstIndex]; 
    }

    public static ConnectionStatistics GetConnectionStatistics()
    {
        List<ConnectionInfo> connections = ActiveConnections.Values.ToList();
        DateTime now = DateTime.UtcNow;

        return new ConnectionStatistics
        {
            ActiveConnectionCount = connections.Count,
            TotalRequestCount = connections.Sum(c => c.RequestCount),
            AverageConnectionDuration = connections.Any() 
                ? TimeSpan.FromTicks((long)connections.Average(c => (now - c.FirstSeen).Ticks))
                : TimeSpan.Zero,
            StreamingConnectionCount = connections.Count(c => c.IsStreaming),
            ConnectionsWithErrors = connections.Count(c => c.ErrorCount > InterceptorConstants.Numbers.Zero),
            OldestConnection = connections.Any() 
                ? connections.Min(c => c.FirstSeen)
                : null
        };
    }
}

internal class ConnectionInfo
{
    public uint ConnectId { get; set; }
    public string ClientHash { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; }
    public DateTime LastActivity { get; set; }
    public int RequestCount { get; set; }
    public int ErrorCount { get; set; }
    public bool IsStreaming { get; set; }
    public string CurrentMethod { get; set; } = string.Empty;
    public string? LastError { get; set; }
}

public class ConnectionStatistics
{
    public int ActiveConnectionCount { get; set; }
    public int TotalRequestCount { get; set; }
    public TimeSpan AverageConnectionDuration { get; set; }
    public int StreamingConnectionCount { get; set; }
    public int ConnectionsWithErrors { get; set; }
    public DateTime? OldestConnection { get; set; }
}