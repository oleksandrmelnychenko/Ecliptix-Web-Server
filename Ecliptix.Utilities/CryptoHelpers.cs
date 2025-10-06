using System.Security.Cryptography;

namespace Ecliptix.Utilities;

public static class CryptoHelpers
{
    private const int DefaultFingerprintLength = 16;

    public static string ComputeSha256Fingerprint(byte[] data, int length = DefaultFingerprintLength)
    {
        byte[] hash = SHA256.HashData(data);
        string hexString = Convert.ToHexString(hash);
        return hexString[..Math.Min(length, hexString.Length)];
    }

    public static string ComputeSha256Fingerprint(ReadOnlySpan<byte> data, int length = DefaultFingerprintLength)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        string hexString = Convert.ToHexString(hash);
        return hexString[..Math.Min(length, hexString.Length)];
    }
}
