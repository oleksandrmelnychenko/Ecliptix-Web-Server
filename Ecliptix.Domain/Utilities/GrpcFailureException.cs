using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public class GrpcFailureException(Status grpcStatus, object? structuredLogPayload = null) : Exception(grpcStatus.Detail)
{
    public Status GrpcStatus { get; } = grpcStatus;
    public object? StructuredLogPayload { get; } = structuredLogPayload;

    public static GrpcFailureException FromDomainFailure(FailureBase failure)
    {
        return new GrpcFailureException(failure.ToGrpcStatus(), failure.ToStructuredLog());
    }
}