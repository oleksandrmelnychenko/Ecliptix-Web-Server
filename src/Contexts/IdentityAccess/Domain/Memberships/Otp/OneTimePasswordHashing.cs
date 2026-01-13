using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Otp;

public static class OneTimePasswordHashing
{
    private const int SaltByteLength = 16;
    private const int SaltBase64Length = 24;
    private const int HashByteLength = 32;
    private const int HashBase64Length = 44;
    private const int StackAllocThreshold = 128;

    public static (string hash, string salt) HashOtp(string otp)
    {
        Span<byte> saltBytes = stackalloc byte[SaltByteLength];
        Span<char> saltChars = stackalloc char[SaltBase64Length];

        RandomNumberGenerator.Fill(saltBytes);
        Convert.TryToBase64Chars(saltBytes, saltChars, out _);

        int combinedMaxBytes = Encoding.UTF8.GetMaxByteCount(otp.Length + SaltBase64Length);
        byte[]? rentedArray = null;
        Span<byte> combinedBytes = combinedMaxBytes <= StackAllocThreshold
            ? stackalloc byte[StackAllocThreshold]
            : rentedArray = ArrayPool<byte>.Shared.Rent(combinedMaxBytes);

        try
        {
            int otpByteCount = Encoding.UTF8.GetBytes(otp, combinedBytes);
            int saltByteCount = Encoding.UTF8.GetBytes(saltChars, combinedBytes[otpByteCount..]);

            Span<byte> hashBytes = stackalloc byte[HashByteLength];
            SHA256.TryHashData(combinedBytes[..(otpByteCount + saltByteCount)], hashBytes, out _);

            Span<char> hashChars = stackalloc char[HashBase64Length];
            Convert.TryToBase64Chars(hashBytes, hashChars, out _);

            return (new string(hashChars), new string(saltChars));
        }
        finally
        {
            if (rentedArray is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedArray);
            }
        }
    }

    public static bool VerifyOtp(string inputOtp, string storedHash, string storedSalt)
    {
        Span<byte> storedHashBytes = stackalloc byte[HashByteLength];
        if (!Convert.TryFromBase64String(storedHash, storedHashBytes, out int bytesWritten)
            || bytesWritten != HashByteLength)
        {
            return false;
        }

        int combinedMaxBytes = Encoding.UTF8.GetMaxByteCount(inputOtp.Length + storedSalt.Length);
        byte[]? rentedArray = null;
        Span<byte> combinedBytes = combinedMaxBytes <= StackAllocThreshold
            ? stackalloc byte[StackAllocThreshold]
            : (rentedArray = ArrayPool<byte>.Shared.Rent(combinedMaxBytes));

        try
        {
            int otpByteCount = Encoding.UTF8.GetBytes(inputOtp, combinedBytes);
            int saltByteCount = Encoding.UTF8.GetBytes(storedSalt, combinedBytes[otpByteCount..]);

            Span<byte> computedHashBytes = stackalloc byte[HashByteLength];
            SHA256.TryHashData(combinedBytes[..(otpByteCount + saltByteCount)], computedHashBytes, out _);

            return CryptographicOperations.FixedTimeEquals(computedHashBytes, storedHashBytes);
        }
        finally
        {
            if (rentedArray is not null)
            {
                ArrayPool<byte>.Shared.Return(rentedArray);
            }
        }
    }
}
