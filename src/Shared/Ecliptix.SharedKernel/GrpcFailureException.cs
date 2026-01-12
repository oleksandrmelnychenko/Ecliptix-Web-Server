using Grpc.Core;

namespace Ecliptix.SharedKernel;

public sealed class GrpcFailureException(
    Status grpcStatus,
    GrpcErrorDescriptor descriptor,
    object? structuredLogPayload = null,
    Exception? innerException = null)
    : Exception(grpcStatus.Detail, innerException)
{
    public Status GrpcStatus { get; } = grpcStatus;
    public GrpcErrorDescriptor Descriptor { get; } = descriptor;
    public object? StructuredLogPayload { get; } = structuredLogPayload;

    public static GrpcFailureException FromDomainFailure(FailureBase failure)
    {
        ClientErrorInfo clientError = failure.ToClientError();
        GrpcErrorDescriptor descriptor = failure.ToGrpcDescriptor();
        return new GrpcFailureException(
            descriptor.CreateStatus(clientError.MessageKey),
            descriptor,
            failure.ToStructuredLog(),
            failure.InnerException);
    }
}
