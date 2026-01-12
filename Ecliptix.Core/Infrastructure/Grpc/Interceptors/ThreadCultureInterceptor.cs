using System.Collections.Concurrent;
using System.Globalization;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public sealed class ThreadCultureInterceptor : Interceptor
{
    private static readonly ConcurrentDictionary<string, CultureInfo> CultureCache = new(StringComparer.OrdinalIgnoreCase);

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request,
        ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation)
    {
        SetThreadCulture(context);
        return await continuation(request, context);
    }

    public override Task ServerStreamingServerHandler<TRequest, TResponse>(TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context, ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        SetThreadCulture(context);
        return base.ServerStreamingServerHandler(request, responseStream, context, continuation);
    }

    private static void SetThreadCulture(ServerCallContext context)
    {
        string clientCulture = GrpcMetadataHandler.GetRequestedLocale(context.RequestHeaders);
        CultureInfo culture = CultureCache.GetOrAdd(clientCulture, static locale => new CultureInfo(locale));
        Thread.CurrentThread.CurrentCulture = culture;
        Thread.CurrentThread.CurrentUICulture = culture;
    }
}
