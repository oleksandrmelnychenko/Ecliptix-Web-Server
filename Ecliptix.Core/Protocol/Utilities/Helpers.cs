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

    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new()
    {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }
}
