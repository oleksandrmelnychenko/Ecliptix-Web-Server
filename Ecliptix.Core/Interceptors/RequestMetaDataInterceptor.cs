using Ecliptix.Domain.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Interceptors;

public sealed class RequestMetaDataInterceptor : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request,
        ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation)
    {
        GrpcMetadataHandler.ValidateRequiredMetaDataParams(context.RequestHeaders);

        string mobileDeviceAppId = GrpcMetadataHandler.GetMobileDeviceAppId(context.RequestHeaders);
        context.UserState[GrpcMetadataHandler.MobileDeviceAppId] = mobileDeviceAppId;

        return await continuation(request, context);
    }
}