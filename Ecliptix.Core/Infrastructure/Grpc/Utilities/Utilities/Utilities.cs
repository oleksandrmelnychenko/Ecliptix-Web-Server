using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public static class ServiceUtilities
{
    public static uint ExtractConnectId(ServerCallContext context)
    {
        return (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];
    }
}