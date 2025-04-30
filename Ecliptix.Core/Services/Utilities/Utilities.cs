using System.Runtime.InteropServices;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Core.Services.Utilities;

public static class ServiceUtilities
{
    private const string InvalidPayloadDataLengthMessage = "Invalid payload data length.";

    public static byte[] ReadMemoryToRetrieveBytes(ReadOnlyMemory<byte> readOnlyMemory)
    {
        if (!MemoryMarshal.TryGetArray(readOnlyMemory, out ArraySegment<byte> segment) || segment.Count == 0)
        {
            throw new ArgumentException(InvalidPayloadDataLengthMessage);
        }

        return segment.Array!;
    }

    public static ByteString GuidToByteString(Guid guid)
    {
        byte[] bytes = guid.ToByteArray();
        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);
        return ByteString.CopyFrom(bytes);
    }

    public static Guid FromByteStringToGuid(ByteString byteString)
    {
        byte[] bytes = byteString.ToByteArray();

        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);

        return new Guid(bytes);
    }

    public static async Task<byte[]> ExtractCipherPayload(ByteString requestedEncryptedPayload, string connectionId,
        Func<byte[], string, int, Task<byte[]>> decryptPayloadFun)
    {
        byte[] encryptedPayload = ReadMemoryToRetrieveBytes(requestedEncryptedPayload.Memory);
        return await decryptPayloadFun(encryptedPayload, connectionId, 0);
    }

    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new()
    {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }

    public static uint ExtractConnectId(ServerCallContext context) =>
        (uint)context.UserState[GrpcMetadataHandler.UniqueConnectId];
}