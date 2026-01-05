using System.Security.Cryptography;
using Ecliptix.SharedKernel.Failures.Sodium;

namespace Ecliptix.SharedKernel.KeyDerivation;

using System.Text;

/// <summary>
/// HKDF-based derivations used for logout proof/HMAC validation in membership flows.
/// </summary>
public static class LogoutKeyDerivation
{
    private const int KeySize = 32;
    private const int HmacSize = 32;

    private const string LogoutHmacKeyInfo = "ecliptix-logout-hmac-v1";
    private const string LogoutProofKeyInfo = "ecliptix-logout-proof-v1";
    private static readonly byte[] LogoutHmacKeyInfoBytes = Encoding.UTF8.GetBytes(LogoutHmacKeyInfo);
    private static readonly byte[] LogoutProofKeyInfoBytes = Encoding.UTF8.GetBytes(LogoutProofKeyInfo);

    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key bytes";
    private const string ErrorMessageHkdfDerivationFailed = "HKDF key derivation failed";

    public static Result<byte[], SodiumFailure> DeriveLogoutHmacKey(SodiumSecureMemoryHandle masterKeyHandle)
    {
        byte[]? masterKeyBytes = null;
        byte[]? hmacKey = null;

        try
        {
            Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(KeySize);
            if (readResult.IsErr)
            {
                return Result<byte[], SodiumFailure>.Err(
                    SodiumFailure.InvalidOperation($"{ErrorMessageMasterKeyReadFailed}: {readResult.UnwrapErr().Message}"));
            }

            masterKeyBytes = readResult.Unwrap();
            hmacKey = new byte[KeySize];

            try
            {
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    ikm: masterKeyBytes,
                    output: hmacKey,
                    salt: ReadOnlySpan<byte>.Empty,
                    info: LogoutHmacKeyInfoBytes);
            }
            catch (Exception ex)
            {
                Array.Clear(hmacKey);
                return Result<byte[], SodiumFailure>.Err(SodiumFailure.InvalidOperation(ErrorMessageHkdfDerivationFailed, ex));
            }

            return Result<byte[], SodiumFailure>.Ok(hmacKey);
        }
        finally
        {
            if (masterKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
    }

    public static Result<byte[], SodiumFailure> DeriveLogoutProofKey(SodiumSecureMemoryHandle masterKeyHandle)
    {
        byte[]? masterKeyBytes = null;
        byte[]? proofKey = null;

        try
        {
            Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(KeySize);
            if (readResult.IsErr)
            {
                return Result<byte[], SodiumFailure>.Err(
                    SodiumFailure.InvalidOperation($"{ErrorMessageMasterKeyReadFailed}: {readResult.UnwrapErr().Message}"));
            }

            masterKeyBytes = readResult.Unwrap();
            proofKey = new byte[KeySize];

            try
            {
                HKDF.DeriveKey(
                    HashAlgorithmName.SHA256,
                    ikm: masterKeyBytes,
                    output: proofKey,
                    salt: ReadOnlySpan<byte>.Empty,
                    info: LogoutProofKeyInfoBytes);
            }
            catch (Exception ex)
            {
                Array.Clear(proofKey);
                return Result<byte[], SodiumFailure>.Err(SodiumFailure.InvalidOperation(ErrorMessageHkdfDerivationFailed, ex));
            }

            return Result<byte[], SodiumFailure>.Ok(proofKey);
        }
        finally
        {
            if (masterKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
    }

    public static byte[] ComputeHmac(byte[] key, ReadOnlySpan<byte> data)
    {
        using HMACSHA256 hmac = new(key);
        byte[] mac = new byte[HmacSize];
        hmac.TryComputeHash(data, mac, out _);
        return mac;
    }

    public static bool VerifyHmac(byte[] key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> expected)
    {
        byte[] computed = ComputeHmac(key, data);
        return CryptographicOperations.FixedTimeEquals(computed, expected);
    }
}
