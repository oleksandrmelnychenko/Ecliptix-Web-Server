using System.Security.Cryptography;
using Google.Protobuf;

namespace Ecliptix.Core.Protocol.Utilities;

public static class Helpers
{
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

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

    public static byte[] GenerateSecureRandomTag(int tagLengthBytes)
    {
        if (tagLengthBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(tagLengthBytes));
        }
        byte[] tagBytes = new byte[tagLengthBytes];
        Rng.GetBytes(tagBytes);
        return tagBytes;
    }

    internal static void GenerateSecureRandomTag(Span<byte> destination)
    {
        if (destination.IsEmpty)
        {
            throw new ArgumentException(null, nameof(destination));
        }
        Rng.GetBytes(destination);
    }

    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new()
    {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }
}