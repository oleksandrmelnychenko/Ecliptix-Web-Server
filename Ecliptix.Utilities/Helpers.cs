using System.Runtime.InteropServices;
using Google.Protobuf;

namespace Ecliptix.Utilities;

public static class Helpers
{
    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new()
    {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }

    public static ByteString GuidToByteString(Guid guid)
    {
        byte[] bytes = guid.ToByteArray();
        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);

        return ByteString.CopyFrom(bytes);
    }

    public static byte[] ReadMemoryToRetrieveBytes(ReadOnlyMemory<byte> readOnlyMemory)
    {
        if (!MemoryMarshal.TryGetArray(readOnlyMemory, out ArraySegment<byte> segment) || segment.Count == 0)
            throw new ArgumentException("Invalid payload data length.");

        return segment.Array!;
    }

    public static Guid FromByteStringToGuid(ByteString byteString)
    {
        byte[] bytesOriginal = byteString.ToByteArray();
        byte[] bytes = (byte[])bytesOriginal.Clone();

        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);

        Guid result = new Guid(bytes);

        return result;
    }
}