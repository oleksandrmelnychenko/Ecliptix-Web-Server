using Ecliptix.Protobuf.Transport.Common;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing;

internal sealed record DispatchFailure(string ErrorCode, EventMetadata Metadata);
