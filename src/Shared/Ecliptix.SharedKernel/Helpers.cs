using System.Runtime.InteropServices;
using Google.Protobuf;

namespace Ecliptix.SharedKernel;

public static class Helpers
{
    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new()
    {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }

    public static ByteString GuidToByteString(Guid guid)
    {
        Span<byte> bytes = stackalloc byte[16];
        guid.TryWriteBytes(bytes);

        // Swap endianness in-place for first 4 bytes
        (bytes[0], bytes[1], bytes[2], bytes[3]) = (bytes[3], bytes[2], bytes[1], bytes[0]);
        // Swap bytes 4-5
        (bytes[4], bytes[5]) = (bytes[5], bytes[4]);
        // Swap bytes 6-7
        (bytes[6], bytes[7]) = (bytes[7], bytes[6]);

        return ByteString.CopyFrom(bytes);
    }

    public static byte[] ReadMemoryToRetrieveBytes(ReadOnlyMemory<byte> readOnlyMemory)
    {
        if (!MemoryMarshal.TryGetArray(readOnlyMemory, out ArraySegment<byte> segment) || segment.Count == 0)
        {
            throw new ArgumentException("Invalid payload data length.");
        }

        return segment.Array!;
    }

    public static Guid FromByteStringToGuid(ByteString byteString)
    {
        Span<byte> bytes = stackalloc byte[16];
        byteString.Span.CopyTo(bytes);

        // Swap endianness in-place for first 4 bytes
        (bytes[0], bytes[1], bytes[2], bytes[3]) = (bytes[3], bytes[2], bytes[1], bytes[0]);
        // Swap bytes 4-5
        (bytes[4], bytes[5]) = (bytes[5], bytes[4]);
        // Swap bytes 6-7
        (bytes[6], bytes[7]) = (bytes[7], bytes[6]);

        return new Guid(bytes);
    }
}
