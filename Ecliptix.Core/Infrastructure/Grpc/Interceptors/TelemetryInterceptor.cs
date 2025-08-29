using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Serilog;
using Ecliptix.Core.Infrastructure.Grpc.Constants;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class TelemetryInterceptor : Interceptor, IDisposable
{
    private static readonly ActivitySource ActivitySource = new(InterceptorConstants.Telemetry.GrpcInterceptorsActivitySource);
    private static readonly ConcurrentDictionary<string, DateTime> LastLogTimes = new();
    private static readonly TimeSpan LogThrottleInterval = TimeSpan.FromSeconds(InterceptorConstants.Thresholds.LogThrottleIntervalSeconds);
    private static readonly Meter TelemetryMeter = new(InterceptorConstants.Telemetry.GrpcTelemetryMeter);
    private static readonly Counter<int> RequestsTotal = TelemetryMeter.CreateCounter<int>(
        InterceptorConstants.Metrics.GrpcRequestsTotal, 
        description: InterceptorConstants.Metrics.GrpcRequestsTotalDescription);

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        using Activity? activity = ActivitySource.StartActivity(InterceptorConstants.Activities.GrpcUnaryCall);
        Stopwatch stopwatch = Stopwatch.StartNew();

        string methodName = context.Method;
        string clientHash = GetClientIdentifierHash(context);
        string userAgent = SanitizeUserAgent(context.GetHttpContext().Request.Headers.UserAgent.ToString());

        activity?.SetTag(InterceptorConstants.Tags.GrpcMethod, methodName);
        activity?.SetTag(InterceptorConstants.Tags.GrpcClientHash, clientHash);
        activity?.SetTag(InterceptorConstants.Tags.GrpcUserAgent, userAgent);
        activity?.SetTag(InterceptorConstants.Tags.GrpcRequestSize, EstimateRequestSize(request));

        try
        {
            LogRateLimited($"{InterceptorConstants.LogPrefixes.GrpcStart}{methodName}", 
                () => Log.Debug("Starting gRPC call {Method}", methodName));

            RequestsTotal.Add(1);
            TResponse response = await continuation(request, context);

            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, InterceptorConstants.StatusMessages.Ok);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcResponseSize, EstimateResponseSize(response));

            LogRateLimited($"{InterceptorConstants.LogPrefixes.GrpcSuccess}{methodName}", 
                () => Log.Information("Completed gRPC call {Method} in {Duration}ms - Status: OK", 
                    methodName, duration));

            if (duration > InterceptorConstants.Thresholds.SlowRequestThresholdMs)
            {
                Log.Warning("Slow gRPC call detected: {Method} took {Duration}ms", 
                    methodName, duration);
            }

            return response;
        }
        catch (RpcException rpcEx)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, rpcEx.StatusCode.ToString());
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcError, true);

            Log.Warning("gRPC call {Method} failed with {StatusCode} in {Duration}ms: {Message}", 
                methodName, rpcEx.StatusCode, duration, rpcEx.Message);

            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, InterceptorConstants.StatusMessages.Internal);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcError, true);

            Log.Error(ex, "Unexpected error in gRPC call {Method} after {Duration}ms", 
                methodName, duration);

            throw;
        }
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        using Activity? activity = ActivitySource.StartActivity(InterceptorConstants.Activities.GrpcServerStreamingCall);
        Stopwatch stopwatch = Stopwatch.StartNew();

        string methodName = context.Method;
        string clientHash = GetClientIdentifierHash(context);

        activity?.SetTag(InterceptorConstants.Tags.GrpcMethod, methodName);
        activity?.SetTag(InterceptorConstants.Tags.GrpcClientHash, clientHash);
        activity?.SetTag(InterceptorConstants.Tags.GrpcStreaming, true);
        activity?.SetTag(InterceptorConstants.Tags.GrpcRequestSize, EstimateRequestSize(request));

        try
        {
            Log.Debug("Starting gRPC streaming call {Method} from client {ClientHash}", methodName, clientHash);

            TelemetryServerStreamWriter<TResponse> wrappedStream = new TelemetryServerStreamWriter<TResponse>(responseStream, activity);

            await continuation(request, wrappedStream, context);

            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, InterceptorConstants.StatusMessages.Ok);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcMessagesSent, wrappedStream.MessagesSent);

            Log.Information("Completed gRPC streaming call {Method} in {Duration}ms from client {ClientHash} - Messages: {Count}", 
                methodName, duration, clientHash, wrappedStream.MessagesSent);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcError, true);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);

            Log.Error(ex, "Error in gRPC streaming call {Method} after {Duration}ms from client {ClientHash}", 
                methodName, duration, clientHash);

            throw;
        }
    }

    private static int EstimateRequestSize<T>(T request)
    {
        try
        {
            return request switch
            {
                Google.Protobuf.IMessage message => message.CalculateSize(),
                _ => 0
            };
        }
        catch
        {
            return 0;
        }
    }

    private static int EstimateResponseSize<T>(T response)
    {
        try
        {
            return response switch
            {
                Google.Protobuf.IMessage message => message.CalculateSize(),
                _ => 0
            };
        }
        catch
        {
            return 0;
        }
    }

    private static void LogRateLimited(string key, Action logAction)
    {
        DateTime now = DateTime.UtcNow;
        if (!LastLogTimes.TryGetValue(key, out DateTime lastTime) || 
            now - lastTime >= LogThrottleInterval)
        {
            LastLogTimes.AddOrUpdate(key, now, (_, _) => now);
            logAction();

            if (LastLogTimes.Count > InterceptorConstants.Limits.MaxLogTimesCount)
            {
                DateTime cutoff = now - TimeSpan.FromMinutes(InterceptorConstants.Thresholds.CacheCleanupIntervalMinutes);
                List<string> toRemove = LastLogTimes
                    .Where(kvp => kvp.Value < cutoff)
                    .Take(InterceptorConstants.Limits.CleanupBatchSize)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (string oldKey in toRemove)
                {
                    LastLogTimes.TryRemove(oldKey, out _);
                }
            }
        }
    }

    private static string GetClientIdentifierHash(ServerCallContext context)
    {
        try
        {
            string clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? InterceptorConstants.Connections.Unknown;
            string userAgent = context.GetHttpContext().Request.Headers.UserAgent.ToString();
            string combined = $"{clientIp}:{userAgent}";

            return Math.Abs(combined.GetHashCode()).ToString("X8");
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

        return userAgent.Split(' ')[0];
    }

    public void Dispose()
    {
    }
}

internal class TelemetryServerStreamWriter<T>(IServerStreamWriter<T> inner, Activity? activity) : IServerStreamWriter<T>
{
    private int _messagesSent = 0;

    public int MessagesSent => _messagesSent;

    public WriteOptions? WriteOptions
    {
        get => inner.WriteOptions;
        set => inner.WriteOptions = value;
    }

    public async Task WriteAsync(T message)
    {
        await inner.WriteAsync(message);
        Interlocked.Increment(ref _messagesSent);
        activity?.SetTag(InterceptorConstants.Tags.GrpcMessagesSent, _messagesSent);
    }
}