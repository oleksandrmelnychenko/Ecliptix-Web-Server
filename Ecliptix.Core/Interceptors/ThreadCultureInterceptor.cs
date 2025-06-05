
using System.Globalization;
using Ecliptix.Core.Services.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Interceptors;

public sealed class ThreadCultureInterceptor : Interceptor {
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request, ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation) {
        string lang = GrpcMetadataHandler.GetRequestedLocale(context.RequestHeaders);
      
        //["en-US","uk-UA"]
        
        CultureInfo requestedCulture = new("en-US");
        Thread.CurrentThread.CurrentCulture = requestedCulture;
        Thread.CurrentThread.CurrentUICulture = requestedCulture;

        return await continuation(request, context);
    }
}