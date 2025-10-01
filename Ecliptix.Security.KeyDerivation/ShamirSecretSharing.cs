using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;

namespace Ecliptix.Security.KeyDerivation;

public sealed class ShamirSecretSharing : ISecretSharingService
{
    private const int Prime256BitSize = 32;
    private const int DefaultThreshold = 3;
    private const int DefaultTotalShares = 5;
    private const int MinimumShares = 2;
    private const int MaximumShares = 255;
    private const int MaxKeyChunks = 1000;
    private const int MaxKeyLength = 1024 * 1024;
    private const int ShareExpirationDays = 30;

    private static readonly BigInteger Prime256 =
        BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908634671663");

    private TimeSpan ShareExpiration { get; } = TimeSpan.FromDays(ShareExpirationDays);

    private static async Task<Result<KeySplitResult, KeySplittingFailure>> SplitKeyAsync(byte[] key,
        int threshold = DefaultThreshold, int totalShares = DefaultTotalShares, byte[]? hmacKey = null)
    {
        if (threshold < MinimumShares || threshold > totalShares)
            return Result<KeySplitResult, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidThreshold(threshold, totalShares));

        if (totalShares is < MinimumShares or > MaximumShares)
            return Result<KeySplitResult, KeySplittingFailure>.Err(KeySplittingFailure.InvalidShareCount(totalShares));

        if (key.Length > int.MaxValue - Prime256BitSize)
            return Result<KeySplitResult, KeySplittingFailure>.Err(KeySplittingFailure.InvalidKeyLength(key.Length));

        return await Task.Run(() =>
        {
            KeyShare[]? shares = null;
            byte[][]? allSharesData = null;
            BigInteger[]? coefficients = null;

            try
            {
                shares = new KeyShare[totalShares];
                int chunksNeeded = checked((key.Length + Prime256BitSize - 1) / Prime256BitSize);

                if (chunksNeeded > MaxKeyChunks)
                    return Result<KeySplitResult, KeySplittingFailure>.Err(
                        KeySplittingFailure.KeySplittingFailed($"Key requires too many chunks (>{MaxKeyChunks})"));

                allSharesData = new byte[totalShares][];
                for (int i = 0; i < totalShares; i++)
                {
                    allSharesData[i] = new byte[chunksNeeded * (Prime256BitSize + 1) + 4];
                    BitConverter.GetBytes(key.Length).CopyTo(allSharesData[i], 0);
                }

                for (int chunkIndex = 0; chunkIndex < chunksNeeded; chunkIndex++)
                {
                    int startIdx = chunkIndex * Prime256BitSize;
                    int chunkSize = Math.Min(Prime256BitSize, key.Length - startIdx);

                    byte[] chunk = new byte[Prime256BitSize];
                    Array.Copy(key, startIdx, chunk, 0, chunkSize);

                    BigInteger secret = new(chunk, true, true);

                    secret %= Prime256;
                    if (secret < 0) secret += Prime256;

                    coefficients = new BigInteger[threshold];
                    coefficients[0] = secret;

                    for (int i = 1; i < threshold; i++)
                    {
                        byte[] randomBytes = RandomNumberGenerator.GetBytes(Prime256BitSize);
                        BigInteger coeff = new BigInteger(randomBytes, true, true) % Prime256;
                        if (coeff < 0) coeff += Prime256;
                        coefficients[i] = coeff;
                    }

                    for (int x = 1; x <= totalShares; x++)
                    {
                        BigInteger shareValue = EvaluatePolynomial(coefficients, x);

                        byte[] shareBytes = shareValue.ToByteArray(true, true);

                        if (shareBytes.Length != Prime256BitSize)
                        {
                            byte[] adjustedBytes = new byte[Prime256BitSize];
                            if (shareBytes.Length > Prime256BitSize)
                            {
                                Array.Copy(shareBytes, shareBytes.Length - Prime256BitSize,
                                    adjustedBytes, 0, Prime256BitSize);
                            }
                            else
                            {
                                Array.Copy(shareBytes, 0, adjustedBytes,
                                    Prime256BitSize - shareBytes.Length, shareBytes.Length);
                            }

                            shareBytes = adjustedBytes;
                        }

                        int shareOffset = 4 + chunkIndex * (Prime256BitSize + 1);
                        allSharesData[x - 1][shareOffset] = (byte)x;
                        Array.Copy(shareBytes, 0, allSharesData[x - 1], shareOffset + 1, Prime256BitSize);
                    }
                }

                KeySplitResult result = new(null!, threshold);
                Guid sessionId = result.SessionId;

                for (int i = 0; i < totalShares; i++)
                {
                    ShareLocation location = (ShareLocation)(i % Enum.GetValues<ShareLocation>().Length);
                    shares[i] = new KeyShare(allSharesData[i], i + 1, location, sessionId);

                    if (hmacKey is not { Length: > 0 }) continue;
                    using HMACSHA256 hmac = new(hmacKey);
                    byte[] shareHmac = hmac.ComputeHash(allSharesData[i]);
                    shares[i].SetHmac(shareHmac);
                }

                result.SetShares(shares);

                return Result<KeySplitResult, KeySplittingFailure>.Ok(result);
            }
            catch (Exception ex)
            {
                if (shares != null)
                {
                    foreach (KeyShare share in shares)
                    {
                        share?.Dispose();
                    }
                }

                return Result<KeySplitResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed(ex.Message, ex));
            }
            finally
            {
                if (coefficients != null)
                {
                    for (int i = 0; i < coefficients.Length; i++)
                    {
                        coefficients[i] = BigInteger.Zero;
                    }
                }

                if (allSharesData != null && shares == null)
                {
                    foreach (byte[] data in allSharesData)
                    {
                        CryptographicOperations.ZeroMemory(data);
                    }
                }
            }
        });
    }

    private async Task<Result<byte[], KeySplittingFailure>> ReconstructMasterKeyAsync(KeyShare[] shares,
        byte[]? hmacKey = null)
    {
        if (shares.Length < MinimumShares)
            return Result<byte[], KeySplittingFailure>.Err(
                KeySplittingFailure.InsufficientShares(shares.Length, MinimumShares));

        if (!ValidateSharesForReconstruction(shares, hmacKey, out string validationError))
            return Result<byte[], KeySplittingFailure>.Err(KeySplittingFailure.ShareValidationFailed(validationError));

        return await Task.Run(() =>
        {
            try
            {
                if (shares[0].ShareData.Length < 4)
                    return Result<byte[], KeySplittingFailure>.Err(
                        KeySplittingFailure.InvalidShareData("Invalid share format: missing length header"));

                int keyLength = BitConverter.ToInt32(shares[0].ShareData, 0);

                if (keyLength is <= 0 or > MaxKeyLength)
                    return Result<byte[], KeySplittingFailure>.Err(KeySplittingFailure.InvalidKeyLength(keyLength));

                int chunksNeeded = checked((keyLength + Prime256BitSize - 1) / Prime256BitSize);

                byte[] reconstructedKey = new byte[keyLength];

                for (int chunkIndex = 0; chunkIndex < chunksNeeded; chunkIndex++)
                {
                    BigInteger[] x = new BigInteger[shares.Length];
                    BigInteger[] y = new BigInteger[shares.Length];

                    for (int i = 0; i < shares.Length; i++)
                    {
                        int shareOffset = 4 + chunkIndex * (Prime256BitSize + 1);

                        if (shareOffset >= shares[i].ShareData.Length)
                            return Result<byte[], KeySplittingFailure>.Err(
                                KeySplittingFailure.InvalidShareData(
                                    $"Invalid share format at index {i}, chunk {chunkIndex}"));

                        if (shareOffset + 1 + Prime256BitSize > shares[i].ShareData.Length)
                            return Result<byte[], KeySplittingFailure>.Err(
                                KeySplittingFailure.InvalidShareData(
                                    $"Share data truncated at index {i}, chunk {chunkIndex}"));

                        x[i] = shares[i].ShareData[shareOffset];

                        byte[] yBytes = new byte[Prime256BitSize];
                        Array.Copy(shares[i].ShareData, shareOffset + 1, yBytes, 0, Prime256BitSize);
                        y[i] = new BigInteger(yBytes, true, true);
                    }

                    BigInteger reconstructedSecret = LagrangeInterpolation(x, y, 0);

                    byte[] secretBytes = reconstructedSecret.ToByteArray(true, true);
                    int startIdx = chunkIndex * Prime256BitSize;
                    int copySize = Math.Min(secretBytes.Length, Math.Min(Prime256BitSize, keyLength - startIdx));
                    Array.Copy(secretBytes, 0, reconstructedKey, startIdx, copySize);
                }

                return Result<byte[], KeySplittingFailure>.Ok(reconstructedKey);
            }
            catch (Exception ex)
            {
                return Result<byte[], KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyReconstructionFailed(ex.Message, ex));
            }
        });
    }

    private static bool ValidateShares(KeyShare[] shares, byte[]? hmacKey = null)
    {
        if (shares.Length < MinimumShares)
            return false;

        try
        {
            int expectedLength = shares[0].ShareData.Length;
            if (shares.Any(s => s.ShareData.Length != expectedLength))
                return false;

            HashSet<int> seenIndices = [];
            if (shares.Any(share => !seenIndices.Add(share.ShareIndex)))
            {
                return false;
            }

            Guid? sessionId = shares[0].SessionId;
            if (shares.Any(s => s.SessionId != sessionId))
                return false;

            if (shares.Any(s => s.ShareIndex < 1 || s.ShareIndex > MaximumShares))
                return false;

            if (hmacKey is { Length: > 0 })
            {
                using HMACSHA256 hmac = new(hmacKey);
                foreach (KeyShare share in shares)
                {
                    if (share.Hmac == null || share.Hmac.Length == 0)
                        return false;

                    byte[] expectedHmac = hmac.ComputeHash(share.ShareData);
                    if (!ConstantTimeEquals(expectedHmac, share.Hmac))
                        return false;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool ValidateSharesForReconstruction(KeyShare[] shares, byte[]? hmacKey, out string error)
    {
        error = string.Empty;

        if (!ValidateShares(shares, hmacKey))
        {
            error = "Share validation failed";
            return false;
        }

        if (ShareExpiration > TimeSpan.Zero)
        {
            DateTime now = DateTime.UtcNow;
            foreach (KeyShare share in shares)
            {
                if (now - share.CreatedAt > ShareExpiration)
                {
                    error = $"Share {share.ShareIndex} has expired (created {share.CreatedAt:yyyy-MM-dd})";
                    return false;
                }
            }
        }

        return true;
    }

    public async Task<Result<Unit, KeySplittingFailure>> SecurelyDisposeSharesAsync(KeyShare[]? shares)
    {
        return await Task.Run(() =>
        {
            try
            {
                foreach (KeyShare share in shares ?? [])
                {
                    share.Dispose();
                }

                return Result<Unit, KeySplittingFailure>.Ok(Unit.Value);
            }
            catch (Exception ex)
            {
                return Result<Unit, KeySplittingFailure>.Err(
                    KeySplittingFailure.InvalidKeyData($"Failed to dispose shares: {ex.Message}"));
            }
        });
    }

    private static BigInteger EvaluatePolynomial(BigInteger[] coefficients, int x)
    {
        BigInteger result = 0;
        BigInteger xPower = 1;

        foreach (BigInteger coeff in coefficients)
        {
            result = (result + (coeff * xPower)) % Prime256;
            xPower = (xPower * x) % Prime256;
        }

        while (result < 0)
            result += Prime256;

        return result;
    }

    private static BigInteger LagrangeInterpolation(BigInteger[] x, BigInteger[] y, int targetX)
    {
        BigInteger result = 0;

        for (int i = 0; i < x.Length; i++)
        {
            BigInteger numerator = 1;
            BigInteger denominator = 1;

            for (int j = 0; j < x.Length; j++)
            {
                if (i != j)
                {
                    numerator = (numerator * (targetX - x[j])) % Prime256;
                    denominator = (denominator * (x[i] - x[j])) % Prime256;
                }
            }

            while (denominator < 0)
                denominator += Prime256;

            BigInteger inverseDenominator = ModInverse(denominator, Prime256);
            BigInteger term = (y[i] * numerator * inverseDenominator) % Prime256;

            result = (result + term) % Prime256;
        }

        while (result < 0)
            result += Prime256;

        return result;
    }

    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        if (m <= 1)
            throw new ArgumentException("Modulus must be greater than 1", nameof(m));

        a = a % m;
        if (a < 0) a += m;

        BigInteger gcd = BigInteger.GreatestCommonDivisor(a, m);
        if (gcd != 1)
            throw new InvalidOperationException($"No modular inverse exists for {a} mod {m} (gcd={gcd})");

        BigInteger m0 = m;
        BigInteger x0 = 0;
        BigInteger x1 = 1;

        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;

            m = a % m;
            a = t;
            t = x0;

            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0) x1 += m0;

        return x1;
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;

        uint diff = 0;
        for (int i = 0; i < a.Length; i++)
        {
            diff |= (uint)(a[i] ^ b[i]);
        }

        return diff == 0;
    }

    public async Task<Result<KeySplitResult, KeySplittingFailure>> SplitKeyAsync(
        SodiumSecureMemoryHandle keyHandle,
        int threshold = DefaultThreshold,
        int totalShares = DefaultTotalShares,
        SodiumSecureMemoryHandle? hmacKeyHandle = null)
    {
        if (keyHandle.IsInvalid)
            return Result<KeySplitResult, KeySplittingFailure>.Err(
                KeySplittingFailure.InvalidKeyData("Key handle cannot be null or invalid"));

        byte[]? keyBytes = null;
        byte[]? hmacKeyBytes = null;

        try
        {
            Result<byte[], Ecliptix.Utilities.Failures.Sodium.SodiumFailure> readResult =
                keyHandle.ReadBytes(keyHandle.Length);
            if (readResult.IsErr)
                return Result<KeySplitResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.MemoryReadFailed(readResult.UnwrapErr().Message));

            keyBytes = readResult.Unwrap();

            if (hmacKeyHandle is { IsInvalid: false })
            {
                Result<byte[], Ecliptix.Utilities.Failures.Sodium.SodiumFailure> hmacReadResult =
                    hmacKeyHandle.ReadBytes(hmacKeyHandle.Length);
                if (hmacReadResult.IsErr)
                    return Result<KeySplitResult, KeySplittingFailure>.Err(
                        KeySplittingFailure.HmacKeyRetrievalFailed(hmacReadResult.UnwrapErr().Message));

                hmacKeyBytes = hmacReadResult.Unwrap();
            }

            return await SplitKeyAsync(keyBytes, threshold, totalShares, hmacKeyBytes);
        }
        finally
        {
            if (keyBytes != null)
                CryptographicOperations.ZeroMemory(keyBytes);
            if (hmacKeyBytes != null)
                CryptographicOperations.ZeroMemory(hmacKeyBytes);
        }
    }

    public async Task<Result<SodiumSecureMemoryHandle, KeySplittingFailure>> ReconstructKeyHandleAsync(
        KeyShare[] shares,
        SodiumSecureMemoryHandle? hmacKeyHandle = null)
    {
        byte[]? hmacKeyBytes = null;

        try
        {
            if (hmacKeyHandle is { IsInvalid: false })
            {
                Result<byte[], Ecliptix.Utilities.Failures.Sodium.SodiumFailure> hmacReadResult =
                    hmacKeyHandle.ReadBytes(hmacKeyHandle.Length);
                if (hmacReadResult.IsErr)
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.HmacKeyRetrievalFailed(hmacReadResult.UnwrapErr().Message));

                hmacKeyBytes = hmacReadResult.Unwrap();
            }

            Result<byte[], KeySplittingFailure> reconstructResult =
                await ReconstructMasterKeyAsync(shares, hmacKeyBytes);
            if (reconstructResult.IsErr)
                return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(reconstructResult.UnwrapErr());

            byte[] reconstructedKey = reconstructResult.Unwrap();

            try
            {
                Result<SodiumSecureMemoryHandle, Ecliptix.Utilities.Failures.Sodium.SodiumFailure> allocateResult =
                    SodiumSecureMemoryHandle.Allocate(reconstructedKey.Length);
                if (allocateResult.IsErr)
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.AllocationFailed(allocateResult.UnwrapErr().Message));

                SodiumSecureMemoryHandle handle = allocateResult.Unwrap();

                Result<Unit, Ecliptix.Utilities.Failures.Sodium.SodiumFailure> writeResult =
                    handle.Write(reconstructedKey);
                if (writeResult.IsErr)
                {
                    handle.Dispose();
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.MemoryWriteFailed(writeResult.UnwrapErr().Message));
                }

                return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Ok(handle);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(reconstructedKey);
            }
        }
        finally
        {
            if (hmacKeyBytes != null)
                CryptographicOperations.ZeroMemory(hmacKeyBytes);
        }
    }
}