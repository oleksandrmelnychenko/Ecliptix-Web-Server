using Ecliptix.SharedKernel;
using Grpc.Core;

namespace Ecliptix.SharedKernel.Grpc.Utilities;

public static class ServiceUtilities
{
    private const string UniqueConnectIdKey = "UniqueConnectId";

    public static uint ExtractConnectId(ServerCallContext context)
    {
        return context.UserState.TryGetValue(UniqueConnectIdKey, out object? value) && value is uint id
            ? id
            : 0;
    }

    public static Option<string> ExtractIdempotencyKey(ServerCallContext context)
    {
        string? key = context.RequestHeaders
            .FirstOrDefault(h => h.Key == MetadataConstants.Keys.IdempotencyKey)?.Value;

        return string.IsNullOrWhiteSpace(key) ? Option<string>.None : Option<string>.Some(key);
    }
}
