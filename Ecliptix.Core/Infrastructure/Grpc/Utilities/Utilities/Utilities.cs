using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public static class ServiceUtilities
{
    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new()
    {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }

    public static uint ExtractConnectId(ServerCallContext context)
    {
        return (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];
    }
}