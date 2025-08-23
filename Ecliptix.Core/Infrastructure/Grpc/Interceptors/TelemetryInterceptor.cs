using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class TelemetryInterceptor : Interceptor, IDisposable
{
    private static readonly ActivitySource ActivitySource = new("Ecliptix.GrpcInterceptors");
    private static readonly ConcurrentDictionary<string, DateTime> LastLogTimes = new();
    private static readonly TimeSpan LogThrottleInterval = TimeSpan.FromSeconds(10);
    private static readonly Meter TelemetryMeter = new("Ecliptix.GrpcTelemetry");
    private static readonly Counter<int> RequestsTotal = TelemetryMeter.CreateCounter<int>(
        "grpc_requests_total", 
        description: "Total number of gRPC requests");

    public TelemetryInterceptor()
    {
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        using Activity activity = ActivitySource.StartActivity("GrpcUnaryCall");
        Stopwatch stopwatch = Stopwatch.StartNew();
        
        string methodName = context.Method;
        string clientHash = GetClientIdentifierHash(context);
        string userAgent = SanitizeUserAgent(context.GetHttpContext().Request.Headers.UserAgent.ToString());
        
        activity?.SetTag("grpc.method", methodName);
        activity?.SetTag("grpc.client_hash", clientHash);
        activity?.SetTag("grpc.user_agent", userAgent);
        activity?.SetTag("grpc.request_size", EstimateRequestSize(request));

        try
        {
            LogRateLimited($"grpc_start_{methodName}", 
                () => Log.Debug("Starting gRPC call {Method}", methodName));

            RequestsTotal.Add(1);
            TResponse response = await continuation(request, context);
            
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;
            
            activity?.SetTag("grpc.status", "OK");
            activity?.SetTag("grpc.duration_ms", duration);
            activity?.SetTag("grpc.response_size", EstimateResponseSize(response));
            
            LogRateLimited($"grpc_success_{methodName}", 
                () => Log.Information("Completed gRPC call {Method} in {Duration}ms - Status: OK", 
                    methodName, duration));
                
            if (duration > 5000)
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
            
            activity?.SetTag("grpc.status", rpcEx.StatusCode.ToString());
            activity?.SetTag("grpc.duration_ms", duration);
            activity?.SetTag("grpc.error", true);
            
            Log.Warning("gRPC call {Method} failed with {StatusCode} in {Duration}ms: {Message}", 
                methodName, rpcEx.StatusCode, duration, rpcEx.Message);
            
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;
            
            activity?.SetTag("grpc.status", "INTERNAL");
            activity?.SetTag("grpc.duration_ms", duration);
            activity?.SetTag("grpc.error", true);
            
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
        using Activity activity = ActivitySource.StartActivity("GrpcServerStreamingCall");
        Stopwatch stopwatch = Stopwatch.StartNew();
        
        string methodName = context.Method;
        string clientHash = GetClientIdentifierHash(context);
        
        activity?.SetTag("grpc.method", methodName);
        activity?.SetTag("grpc.client_hash", clientHash);
        activity?.SetTag("grpc.streaming", true);
        activity?.SetTag("grpc.request_size", EstimateRequestSize(request));

        try
        {
            Log.Debug("Starting gRPC streaming call {Method} from client {ClientHash}", methodName, clientHash);

            TelemetryServerStreamWriter<TResponse> wrappedStream = new TelemetryServerStreamWriter<TResponse>(responseStream, activity);
            
            await continuation(request, wrappedStream, context);
            
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;
            
            activity?.SetTag("grpc.status", "OK");
            activity?.SetTag("grpc.duration_ms", duration);
            activity?.SetTag("grpc.messages_sent", wrappedStream.MessagesSent);
            
            Log.Information("Completed gRPC streaming call {Method} in {Duration}ms from client {ClientHash} - Messages: {Count}", 
                methodName, duration, clientHash, wrappedStream.MessagesSent);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;
            
            activity?.SetTag("grpc.error", true);
            activity?.SetTag("grpc.duration_ms", duration);
            
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
            
            if (LastLogTimes.Count > 1000)
            {
                DateTime cutoff = now - TimeSpan.FromMinutes(5);
                List<string> toRemove = LastLogTimes
                    .Where(kvp => kvp.Value < cutoff)
                    .Take(100)
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
            string clientIp = context.GetHttpContext().Connection.RemoteIpAddress?.ToString() ?? "unknown";
            string userAgent = context.GetHttpContext().Request.Headers.UserAgent.ToString();
            string combined = $"{clientIp}:{userAgent}";
            
            return Math.Abs(combined.GetHashCode()).ToString("X8");
        }
        catch
        {
            return "unknown";
        }
    }

    private static string SanitizeUserAgent(string userAgent)
    {
        if (string.IsNullOrEmpty(userAgent) || userAgent.Length > 200)
            return "sanitized";
            
        return userAgent.Split(' ')[0];
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}

internal class TelemetryServerStreamWriter<T> : IServerStreamWriter<T>
{
    private readonly IServerStreamWriter<T> _inner;
    private readonly Activity? _activity;
    private int _messagesSent = 0;

    public TelemetryServerStreamWriter(IServerStreamWriter<T> inner, Activity? activity)
    {
        _inner = inner;
        _activity = activity;
    }

    public int MessagesSent => _messagesSent;

    public WriteOptions? WriteOptions
    {
        get => _inner.WriteOptions;
        set => _inner.WriteOptions = value;
    }

    public async Task WriteAsync(T message)
    {
        await _inner.WriteAsync(message);
        Interlocked.Increment(ref _messagesSent);
        _activity?.SetTag("grpc.messages_sent", _messagesSent);
    }
}