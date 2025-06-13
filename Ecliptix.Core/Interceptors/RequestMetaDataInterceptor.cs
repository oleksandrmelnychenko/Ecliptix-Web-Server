using Ecliptix.Core.Services.Utilities;
using Ecliptix.Domain.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Ecliptix.Core.Interceptors;

public sealed class RequestMetaDataInterceptor : Interceptor
{
    public override Task ServerStreamingServerHandler<TRequest, TResponse>(TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context, ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        Result<Unit, MetaDataSystemFailure> validationResult =
            GrpcMetadataHandler.ValidateRequiredMetaDataParams(context.RequestHeaders);

        if (validationResult.IsErr)
        {
            MetaDataSystemFailure metaDataSystemFailure = validationResult.UnwrapErr();
            string? errorMessage = metaDataSystemFailure.Message;
            if (errorMessage is not null) context.Status = new Status(StatusCode.Internal, errorMessage);

            throw new RpcException(context.Status);
        }

        GrpcMetadataHandler.ComputeUniqueConnectId(context.RequestHeaders)
            .Match(
                uniqueConnectId =>
                {
                    context.UserState[GrpcMetadataHandler.UniqueConnectId] = uniqueConnectId;
                    return Unit.Value;
                },
                error =>
                {
                    context.Status = new Status(StatusCode.Internal, error.Message!);
                    throw new RpcException(context.Status);
                }
            );

        return base.ServerStreamingServerHandler(request, responseStream, context, continuation);
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(TRequest request,
        ServerCallContext context, UnaryServerMethod<TRequest, TResponse> continuation)
    {
        Result<Unit, MetaDataSystemFailure> validationResult =
            GrpcMetadataHandler.ValidateRequiredMetaDataParams(context.RequestHeaders);
        if (validationResult.IsErr)
        {
            MetaDataSystemFailure metaDataSystemFailure = validationResult.UnwrapErr();
            string? errorMessage = metaDataSystemFailure.Message;
            if (errorMessage is not null) context.Status = new Status(StatusCode.Internal, errorMessage);

            throw new RpcException(context.Status);
        }

        GrpcMetadataHandler.ComputeUniqueConnectId(context.RequestHeaders)
            .Match(
                uniqueConnectId =>
                {
                    context.UserState[GrpcMetadataHandler.UniqueConnectId] = uniqueConnectId;
                    return Unit.Value;
                },
                error =>
                {
                    context.Status = new Status(StatusCode.Internal, error.Message!);
                    throw new RpcException(context.Status);
                }
            );

        return await continuation(request, context);
    }
}