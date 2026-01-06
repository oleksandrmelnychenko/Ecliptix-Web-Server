using Grpc.Core;

namespace Ecliptix.SharedKernel;

public sealed class GrpcFailureException : Exception
{
    public GrpcFailureException(
        Status grpcStatus,
        GrpcErrorDescriptor descriptor,
        object? structuredLogPayload = null,
        Exception? innerException = null)
        : base(grpcStatus.Detail, innerException)
    {
        GrpcStatus = grpcStatus;
        Descriptor = descriptor;
        StructuredLogPayload = structuredLogPayload;
    }

    public Status GrpcStatus { get; }
    public GrpcErrorDescriptor Descriptor { get; }
    public object? StructuredLogPayload { get; }

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
