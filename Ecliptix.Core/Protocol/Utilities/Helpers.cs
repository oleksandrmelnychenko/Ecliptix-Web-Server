using System.Security.Cryptography;

namespace Ecliptix.Core.Protocol.Utilities;

public static class Helpers
{
    public static uint GenerateRandomUInt32()
    {
        byte[] randomBytes = new byte[4]; // 4 bytes for a 32-bit integer
        RandomNumberGenerator.Fill(randomBytes);
        return BitConverter.ToUInt32(randomBytes, 0);
    }

}