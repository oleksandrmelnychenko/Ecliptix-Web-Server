using Ecliptix.Protobuf.Transport.Common;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal sealed record DispatchFailure(
    string ErrorCode,
    string MessageKey,
    string LocalizedMessage,
    bool Retryable,
    EventMetadata Metadata);
