using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;
using Ecliptix.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public sealed class RequestMetaDataInterceptor : Interceptor
{
    public override Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        ValidateAndPopulateMetadata(context);
        return base.ServerStreamingServerHandler(request, responseStream, context, continuation);
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        ValidateAndPopulateMetadata(context);
        return await continuation(request, context);
    }

    private static void ValidateAndPopulateMetadata(ServerCallContext context)
    {
        Result<Unit, MetaDataSystemFailure> validationResult =
            GrpcMetadataHandler.ValidateRequiredMetaDataParams(context.RequestHeaders);

        if (validationResult.IsErr)
        {
            throw GrpcFailureException.FromDomainFailure(validationResult.UnwrapErr());
        }

        Result<uint, MetaDataSystemFailure> connectIdResult =
            GrpcMetadataHandler.ComputeUniqueConnectId(context.RequestHeaders);

        if (connectIdResult.IsErr)
        {
            throw GrpcFailureException.FromDomainFailure(connectIdResult.UnwrapErr());
        }

        context.UserState[GrpcMetadataHandler.UniqueConnectId] = connectIdResult.Unwrap();
    }
}
