
using System.Globalization;
using Ecliptix.Domain.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Interceptors;

public sealed class ThreadCultureInterceptor : Interceptor {
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request, ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation) {
        string lang = GrpcMetadataHandler.GetRequestLocale(context.RequestHeaders);
      
        CultureInfo requestedCulture = new(lang);
        Thread.CurrentThread.CurrentCulture = requestedCulture;
        Thread.CurrentThread.CurrentUICulture = requestedCulture;

        return await continuation(request, context);
    }
}