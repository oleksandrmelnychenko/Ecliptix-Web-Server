using System.Security.Cryptography;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures.Sodium;
using Serilog;

namespace Ecliptix.Core.Services.KeyDerivation;

public static class LogoutKeyDerivation
{
    private const int KeySize = 32;
    private const int HmacSize = 32;

    private const string LogoutHmacKeyInfo = "ecliptix-logout-hmac-v1";
    private const string LogoutProofKeyInfo = "ecliptix-logout-proof-v1";

    private const string LogTagLogoutHmacKey = "[LOGOUT-HMAC-KEY]";
    private const string LogTagLogoutProofKey = "[LOGOUT-PROOF-KEY]";

    private const string LogMessageHmacKeyDerived = "{LogTag} Logout HMAC key derived. KeyFingerprint: {KeyFingerprint}";
    private const string LogMessageProofKeyDerived = "{LogTag} Logout proof key derived. KeyFingerprint: {KeyFingerprint}";

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
                    salt: null,
                    info: System.Text.Encoding.UTF8.GetBytes(LogoutHmacKeyInfo)
                );

                string keyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(hmacKey);
                Log.Debug(LogMessageHmacKeyDerived, LogTagLogoutHmacKey, keyFingerprint);

                byte[] result = hmacKey;
                hmacKey = null;
                return Result<byte[], SodiumFailure>.Ok(result);
            }
            catch (CryptographicException ex)
            {
                return Result<byte[], SodiumFailure>.Err(
                    SodiumFailure.InvalidOperation($"{ErrorMessageHkdfDerivationFailed}: {ex.Message}"));
            }
        }
        finally
        {
            if (masterKeyBytes != null)
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            if (hmacKey != null)
                CryptographicOperations.ZeroMemory(hmacKey);
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
                    salt: null,
                    info: System.Text.Encoding.UTF8.GetBytes(LogoutProofKeyInfo)
                );

                string keyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(proofKey);
                Log.Debug(LogMessageProofKeyDerived, LogTagLogoutProofKey, keyFingerprint);

                byte[] result = proofKey;
                proofKey = null;
                return Result<byte[], SodiumFailure>.Ok(result);
            }
            catch (CryptographicException ex)
            {
                return Result<byte[], SodiumFailure>.Err(
                    SodiumFailure.InvalidOperation($"{ErrorMessageHkdfDerivationFailed}: {ex.Message}"));
            }
        }
        finally
        {
            if (masterKeyBytes != null)
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            if (proofKey != null)
                CryptographicOperations.ZeroMemory(proofKey);
        }
    }

    public static byte[] ComputeHmac(byte[] key, byte[] data)
    {
        using HMACSHA256 hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    public static bool VerifyHmac(byte[] key, byte[] data, byte[] expectedHmac)
    {
        if (expectedHmac.Length != HmacSize)
            return false;

        byte[] computedHmac = ComputeHmac(key, data);
        try
        {
            return CryptographicOperations.FixedTimeEquals(computedHmac, expectedHmac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedHmac);
        }
    }
}
