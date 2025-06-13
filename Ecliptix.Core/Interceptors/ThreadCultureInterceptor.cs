using System.Globalization;
using Ecliptix.Core.Services.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Interceptors;

public sealed class ThreadCultureInterceptor : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request,
        ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation)
    {
        string clientCulture = GrpcMetadataHandler.GetRequestedLocale(context.RequestHeaders);

        CultureInfo requestedCulture = new(clientCulture);
        Thread.CurrentThread.CurrentCulture = requestedCulture;
        Thread.CurrentThread.CurrentUICulture = requestedCulture;

        return await continuation(request, context);
    }

    public override Task ServerStreamingServerHandler<TRequest, TResponse>(TRequest request, IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context, ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        string clientCulture = GrpcMetadataHandler.GetRequestedLocale(context.RequestHeaders);

        CultureInfo requestedCulture = new(clientCulture);
        Thread.CurrentThread.CurrentCulture = requestedCulture;
        Thread.CurrentThread.CurrentUICulture = requestedCulture;
        
        return base.ServerStreamingServerHandler(request, responseStream, context, continuation);
    }
}