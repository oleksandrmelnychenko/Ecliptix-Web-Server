using Ecliptix.Domain.Utilities;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Constants;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Interceptors;

public class FailureHandlingInterceptor : Interceptor
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

    private RpcException HandleException(Exception exception, ServerCallContext context)
    {
        switch (exception)
        {
            case GrpcFailureException ex:
                Log.Warning(
                    ex,
                    "gRPC call {Method} terminated by a handled domain failure. Status: {StatusCode}. Details: {@LogPayload}",
                    context.Method,
                    ex.GrpcStatus.StatusCode,
                    ex.StructuredLogPayload
                );
                return new RpcException(ex.GrpcStatus);

            case RpcException ex:
                Log.Warning(ex,
                    "gRPC call {Method} failed with a pre-existing RpcException. Status: {StatusCode}.",
                    context.Method, ex.Status.StatusCode);
                return ex;

            default:
                Log.Error(exception, "An unhandled exception was thrown during gRPC call {Method}.",
                    context.Method);
                Status status = new(StatusCode.Internal, InterceptorConstants.StatusMessages.UnexpectedInternalServerError);
                return new RpcException(status, exception.Message);
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
}