using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Google.Protobuf;

namespace Ecliptix.Utilities;

public static class Helpers
{
    private const string InvalidPayloadDataLengthMessage = "Invalid payload data length.";
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

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

        Console.WriteLine($"[SERVER-GUID-TO-BYTES] GUID: {guid}, Bytes: {Convert.ToHexString(bytes)}");

        return ByteString.CopyFrom(bytes);
    }

    public static byte[] ReadMemoryToRetrieveBytes(ReadOnlyMemory<byte> readOnlyMemory)
    {
        if (!MemoryMarshal.TryGetArray(readOnlyMemory, out ArraySegment<byte> segment) || segment.Count == 0)
            throw new ArgumentException(InvalidPayloadDataLengthMessage);

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

        Console.WriteLine($"[SERVER-BYTES-TO-GUID] Bytes: {Convert.ToHexString(bytesOriginal)}, GUID: {result}");

        return result;
    }
}