using System.Security.Cryptography;
using System.Text;

namespace Ecliptix.Domain.Memberships;

public static class OneTimePasswordHashing
{
    public static (string hash, string salt) HashOtp(string otp)
    {
        byte[] saltBytes = RandomNumberGenerator.GetBytes(16);
        string salt = Convert.ToBase64String(saltBytes);
        byte[] combined = Encoding.UTF8.GetBytes(otp + salt);
        byte[] hashBytes = SHA256.HashData(combined);
        string hash = Convert.ToBase64String(hashBytes);

        return (hash, salt);
    }

    public static bool VerifyOtp(string inputOtp, string storedHash, string storedSalt)
    {
        byte[] combined = Encoding.UTF8.GetBytes(inputOtp + storedSalt);
        byte[] computedHash = SHA256.HashData(combined);
        string resultHash = Convert.ToBase64String(computedHash);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(resultHash),
            Encoding.UTF8.GetBytes(storedHash)
        );
    }
}
