using System.Diagnostics.Metrics;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public sealed class TelemetryInterceptor : Interceptor, IDisposable
{
    private static readonly Meter TelemetryMeter = new(InterceptorConstants.Telemetry.GrpcTelemetryMeter);
    private static readonly Counter<int> RequestsTotal = TelemetryMeter.CreateCounter<int>(
        InterceptorConstants.Metrics.GrpcRequestsTotal,
        description: InterceptorConstants.Metrics.GrpcRequestsTotalDescription);

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        RequestsTotal.Add(InterceptorConstants.Numbers.One);
        return await continuation(request, context);
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        await continuation(request, responseStream, context);
    }

    public void Dispose()
    {
        TelemetryMeter.Dispose();
    }
}
