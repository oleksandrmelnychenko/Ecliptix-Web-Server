using System.Security.Cryptography;
using Google.Protobuf;

namespace Ecliptix.Domain.Utilities;

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

    public static Guid FromByteStringToGuid(ByteString byteString)
    {
        byte[] bytes = byteString.ToByteArray();

        Array.Reverse(bytes, 0, 4);
        Array.Reverse(bytes, 4, 2);
        Array.Reverse(bytes, 6, 2);

        return new Guid(bytes);
    }
}
