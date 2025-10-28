using Ecliptix.Core.Configuration;
using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public static class ServiceUtilities
{
    public static uint ExtractConnectId(ServerCallContext context)
    {
        return (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];
    }

    public static Option<string> ExtractIdempotencyKey(ServerCallContext context)
    {
        string? key = context.RequestHeaders
            .FirstOrDefault(h => h.Key == MetadataConstants.Keys.IdempotencyKey)?.Value;

        return string.IsNullOrWhiteSpace(key) ? Option<string>.None : Option<string>.Some(key);
    }
}
