using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ecliptix.Protobuf.CipherPayload;
using Google.Protobuf;
using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public static class Helpers
{
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
    private const string InvalidPayloadDataLengthMessage = "Invalid payload data length.";

    public static uint GenerateRandomUInt32(bool excludeZero = false)
    {
        byte[] buffer = new byte[sizeof(uint)];
        uint value;
        do
        {
            Rng.GetBytes(buffer);
            value = BitConverter.ToUInt32(buffer, 0);
        } while (excludeZero && value == 0);

        return value;
    }

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
        {
            throw new ArgumentException(InvalidPayloadDataLengthMessage);
        }

        return segment.Array!;
    }

    public static Guid FromByteStringToGuid(ByteString byteString)
    {
        byte[] bytes = byteString.ToByteArray();

        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);

        return new Guid(bytes);
    }
}