using System.Diagnostics;
using System.Diagnostics.Metrics;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class TelemetryInterceptor : Interceptor, IDisposable
{
    private static readonly ActivitySource ActivitySource = new(InterceptorConstants.Telemetry.GrpcInterceptorsActivitySource);
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
            RequestsTotal.Add(InterceptorConstants.Numbers.One);
            TResponse response = await continuation(request, context);

            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, InterceptorConstants.StatusMessages.Ok);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcResponseSize, EstimateResponseSize(response));

            return response;
        }
        catch (RpcException rpcEx)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, rpcEx.StatusCode.ToString());
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcError, true);

            throw;
        }
        catch (Exception)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, InterceptorConstants.StatusMessages.Internal);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcError, true);

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
            TelemetryServerStreamWriter<TResponse> wrappedStream = new TelemetryServerStreamWriter<TResponse>(responseStream, activity);

            await continuation(request, wrappedStream, context);

            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcStatus, InterceptorConstants.StatusMessages.Ok);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);
            activity?.SetTag(InterceptorConstants.Tags.GrpcMessagesSent, wrappedStream.MessagesSent);
        }
        catch (Exception)
        {
            stopwatch.Stop();
            long duration = stopwatch.ElapsedMilliseconds;

            activity?.SetTag(InterceptorConstants.Tags.GrpcError, true);
            activity?.SetTag(InterceptorConstants.Tags.GrpcDurationMs, duration);

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
                _ => InterceptorConstants.Numbers.Zero
            };
        }
        catch
        {
            return InterceptorConstants.Numbers.Zero;
        }
    }

    private static int EstimateResponseSize<T>(T response)
    {
        try
        {
            return response switch
            {
                Google.Protobuf.IMessage message => message.CalculateSize(),
                _ => InterceptorConstants.Numbers.Zero
            };
        }
        catch
        {
            return InterceptorConstants.Numbers.Zero;
        }
    }


    private static string GetClientIdentifierHash(ServerCallContext context)
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
        {
            return InterceptorConstants.Connections.Sanitized;
        }

        return userAgent.Split(InterceptorConstants.Characters.Space)[InterceptorConstants.Numbers.FirstIndex];
    }

    public void Dispose()
    {
    }
}

internal class TelemetryServerStreamWriter<T>(IServerStreamWriter<T> inner, Activity? activity) : IServerStreamWriter<T>
{
    private int _messagesSent = InterceptorConstants.Numbers.Zero;

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
