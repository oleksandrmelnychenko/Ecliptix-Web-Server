using Grpc.Core;
using Grpc.Core.Interceptors;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Interceptors;

public class FailureHandlingInterceptor(ILogger<FailureHandlingInterceptor> logger) : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        try
        {
            return await continuation(request, context);
        }
        catch (Exception ex)
        {
            throw HandleException(ex, context);
        }
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        try
        {
            SafeStreamWriter<TResponse> wrappedStream = new(responseStream, context, this);
            await continuation(request, wrappedStream, context);
        }
        catch (Exception ex)
        {
            throw HandleException(ex, context);
        }
    }

    private class SafeStreamWriter<TResponse>(
        IServerStreamWriter<TResponse> innerWriter,
        ServerCallContext context,
        FailureHandlingInterceptor interceptor)
        : IServerStreamWriter<TResponse>
    {
        public WriteOptions? WriteOptions
        {
            get => innerWriter.WriteOptions;
            set => innerWriter.WriteOptions = value;
        }

        public async Task WriteAsync(TResponse message)
        {
            try
            {
                await innerWriter.WriteAsync(message);
            }
            catch (Exception ex)
            {
                throw interceptor.HandleException(ex, context);
            }
        }
    }

    private RpcException HandleException(Exception exception, ServerCallContext context)
    {
        switch (exception)
        {
            case GrpcFailureException ex:
                logger.LogWarning(
                    ex,
                    "gRPC call {Method} terminated by a handled domain failure. Status: {StatusCode}. Details: {@LogPayload}",
                    context.Method,
                    ex.GrpcStatus.StatusCode,
                    ex.StructuredLogPayload
                );
                return new RpcException(ex.GrpcStatus);

            case RpcException ex:
                logger.LogWarning(ex,
                    "gRPC call {Method} failed with a pre-existing RpcException. Status: {StatusCode}.",
                    context.Method, ex.Status.StatusCode);
                return ex; 

            default:
                logger.LogError(exception, "An unhandled exception was thrown during gRPC call {Method}.",
                    context.Method);
                Status status = new Status(StatusCode.Internal, "An unexpected internal server error occurred.");
                return new RpcException(status, exception.Message);
        }
    }
}