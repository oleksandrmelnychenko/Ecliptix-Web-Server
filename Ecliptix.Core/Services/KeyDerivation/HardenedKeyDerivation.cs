using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Ecliptix.Utilities.Failures.Sodium;
using Konscious.Security.Cryptography;
using Serilog.Events;

namespace Ecliptix.Core.Services.KeyDerivation;

public sealed class HardenedKeyDerivation : IHardenedKeyDerivation
{
    private const string KeyContextPrefix = "ecliptix-session-key";
    private const string RoundKeyFormat = "round-{0}";
    private const int AdditionalRoundsCount = 3;
    private const int MaxInfoBufferSize = 128;
    private const int MaxPreviousBlockSize = 64;
    private const int MaxRoundBufferSize = 64;
    private const int CounterIncrement = 1;
    private const int StartingCounter = 1;
    private const int FirstRoundIndex = 0;

    private const string LogTagServerEnhancedArgon2Id = "[SERVER-ENHANCED-ARGON2ID]";
    private const string LogTagServerEnhancedHkdf = "[SERVER-ENHANCED-HKDF]";
    private const string LogTagServerEnhancedFinal = "[SERVER-ENHANCED-FINAL]";

    private const string LogMessageArgon2IdCompleted =
        "{LogTag} Enhanced key Argon2id stretch completed. Context: {Context}, StretchedKeyFingerprint: {StretchedKeyFingerprint}";

    private const string LogMessageHkdfCompleted =
        "{LogTag} Enhanced key HKDF expansion completed. Context: {Context}, ExpandedKeyFingerprint: {ExpandedKeyFingerprint}";

    private const string LogMessageFinalCompleted =
        "{LogTag} Enhanced key final (after additional rounds). Context: {Context}, FinalKeyFingerprint: {FinalKeyFingerprint}";

    public async Task<Result<SodiumSecureMemoryHandle, KeySplittingFailure>> DeriveEnhancedMasterKeyHandleAsync(
        SodiumSecureMemoryHandle baseKeyHandle,
        string context,
        KeyDerivationOptions options)
    {
        byte[]? baseKeyBytes = null;

        try
        {
            Result<byte[], SodiumFailure> readResult =
                baseKeyHandle.ReadBytes(baseKeyHandle.Length);
            if (readResult.IsErr)
            {
                SodiumFailure error = readResult.UnwrapErr();
                return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                    KeySplittingFailure.MemoryReadFailed(error.Message));
            }

            baseKeyBytes = readResult.Unwrap();

            Result<byte[], KeySplittingFailure> deriveResult =
                await DeriveEnhancedKeyAsync(baseKeyBytes, context, options);
            if (deriveResult.IsErr)
            {
                KeySplittingFailure error = deriveResult.UnwrapErr();
                return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(error);
            }

            byte[] derivedKey = deriveResult.Unwrap();

            try
            {
                Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                    SodiumSecureMemoryHandle.Allocate(derivedKey.Length);
                if (allocateResult.IsErr)
                {
                    SodiumFailure error = allocateResult.UnwrapErr();
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.AllocationFailed(error.Message));
                }

                SodiumSecureMemoryHandle handle = allocateResult.Unwrap();

                Result<Unit, SodiumFailure> writeResult = handle.Write(derivedKey);
                if (!writeResult.IsErr)
                {
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Ok(handle);
                }

                {
                    handle.Dispose();
                    SodiumFailure error = writeResult.UnwrapErr();
                    return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                        KeySplittingFailure.MemoryWriteFailed(error.Message));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedKey);
            }
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed(ex.Message, ex));
        }
        finally
        {
            if (baseKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(baseKeyBytes);
            }
        }
    }

    private async Task<Result<byte[], KeySplittingFailure>> DeriveEnhancedKeyAsync(
        byte[] baseKey,
        string context,
        KeyDerivationOptions options)
    {
        try
        {
            byte[] salt = GenerateContextSalt(context);

            Result<byte[], KeySplittingFailure> stretchedResult =
                await StretchKeyAsync(baseKey, salt, options.OutputLength, options);
            if (stretchedResult.IsErr)
            {
                return stretchedResult;
            }

            byte[] stretchedKey = stretchedResult.Unwrap();

            if (Serilog.Log.IsEnabled(LogEventLevel.Debug))
            {
                string stretchedKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(stretchedKey);
                Serilog.Log.Debug(LogMessageArgon2IdCompleted,
                    LogTagServerEnhancedArgon2Id,
                    context,
                    stretchedKeyFingerprint);
            }

            byte[] expandedKey = await ExpandKeyWithHkdfAsync(stretchedKey, context, options.OutputLength);

            if (Serilog.Log.IsEnabled(LogEventLevel.Debug))
            {
                string expandedKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(expandedKey);
                Serilog.Log.Debug(LogMessageHkdfCompleted,
                    LogTagServerEnhancedHkdf,
                    context,
                    expandedKeyFingerprint);
            }

            if (options.UseHardwareEntropy)
            {
                byte[]? hwEntropy = null;
                try
                {
                    hwEntropy = RandomNumberGenerator.GetBytes(options.OutputLength);
                    for (int i = 0; i < expandedKey.Length && i < hwEntropy.Length; i++)
                    {
                        expandedKey[i] ^= hwEntropy[i];
                    }
                }
                finally
                {
                    if (hwEntropy != null)
                    {
                        CryptographicOperations.ZeroMemory(hwEntropy);
                    }
                }
            }

            byte[] finalKey = await ApplyAdditionalRoundsAsync(expandedKey);

            if (Serilog.Log.IsEnabled(LogEventLevel.Debug))
            {
                string finalKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(finalKey);
                Serilog.Log.Debug(LogMessageFinalCompleted,
                    LogTagServerEnhancedFinal,
                    context,
                    finalKeyFingerprint);
            }

            CryptographicOperations.ZeroMemory(stretchedKey);
            CryptographicOperations.ZeroMemory(expandedKey);

            return Result<byte[], KeySplittingFailure>.Ok(finalKey);
        }
        catch (Exception ex)
        {
            return Result<byte[], KeySplittingFailure>.Err(KeySplittingFailure.KeyDerivationFailed(ex.Message, ex));
        }
    }

    private static async Task<Result<byte[], KeySplittingFailure>> StretchKeyAsync(
        byte[] input,
        byte[] salt,
        int outputLength,
        KeyDerivationOptions options)
    {
        try
        {
            return await Task.Run(() =>
            {
                using Argon2id argon2 = new(input)
                {
                    Salt = salt,
                    DegreeOfParallelism = options.DegreeOfParallelism,
                    Iterations = options.Iterations,
                    MemorySize = options.MemorySize
                };

                byte[] hash = argon2.GetBytes(outputLength);
                return Result<byte[], KeySplittingFailure>.Ok(hash);
            });
        }
        catch (Exception ex)
        {
            return Result<byte[], KeySplittingFailure>.Err(KeySplittingFailure.KeyDerivationFailed(ex.Message, ex));
        }
    }

    private static byte[] GenerateContextSalt(string context)
    {
        string saltInput = $"{KeyContextPrefix}:{context}";
        byte[] saltBytes = SHA256.HashData(Encoding.UTF8.GetBytes(saltInput));
        return saltBytes;
    }

    private static async Task<byte[]> ExpandKeyWithHkdfAsync(byte[] key, string context, int outputLength)
    {
        return await Task.Run(() =>
        {
            Span<byte> infoBuffer = stackalloc byte[MaxInfoBufferSize];
            int infoLength = Encoding.UTF8.GetBytes($"{KeyContextPrefix}-{context}", infoBuffer);
            ReadOnlySpan<byte> info = infoBuffer[..infoLength];

            byte[] salt = SHA256.HashData(Encoding.UTF8.GetBytes(context));

            byte[] pseudoRandomKey;
            using (HMACSHA512 hmac = new(salt))
            {
                pseudoRandomKey = hmac.ComputeHash(key);
            }

            byte[] expandedKey = new byte[outputLength];
            int bytesGenerated = 0;

            using HMACSHA512 expandHmac = new(pseudoRandomKey);
            byte[] previousBlock = [];

            const int maxDataToHashSize = MaxPreviousBlockSize + MaxInfoBufferSize + CounterIncrement;
            byte[] dataToHashBuffer = ArrayPool<byte>.Shared.Rent(maxDataToHashSize);

            try
            {
                for (int i = StartingCounter; bytesGenerated < outputLength; i++)
                {
                    int offset = 0;
                    previousBlock.CopyTo(dataToHashBuffer, offset);
                    offset += previousBlock.Length;
                    info.CopyTo(dataToHashBuffer.AsSpan(offset));
                    offset += info.Length;
                    dataToHashBuffer[offset] = (byte)i;
                    offset++;

                    byte[] currentBlock = expandHmac.ComputeHash(dataToHashBuffer, 0, offset);

                    int bytesToCopy = Math.Min(currentBlock.Length, outputLength - bytesGenerated);
                    Array.Copy(currentBlock, 0, expandedKey, bytesGenerated, bytesToCopy);

                    bytesGenerated += bytesToCopy;
                    previousBlock = currentBlock;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(dataToHashBuffer, clearArray: true);
            }

            CryptographicOperations.ZeroMemory(pseudoRandomKey);
            return expandedKey;
        });
    }

    private static async Task<byte[]> ApplyAdditionalRoundsAsync(byte[] key)
    {
        return await Task.Run(() =>
        {
            byte[] result = (byte[])key.Clone();

            Span<byte> roundBuffer = stackalloc byte[MaxRoundBufferSize];

            for (int round = FirstRoundIndex; round < AdditionalRoundsCount; round++)
            {
                using HMACSHA512 hmac = new(result);
                int roundInputLength = Encoding.UTF8.GetBytes(string.Format(RoundKeyFormat, round), roundBuffer);
                byte[] roundKey = hmac.ComputeHash(roundBuffer[..roundInputLength].ToArray());

                for (int i = 0; i < result.Length && i < roundKey.Length; i++)
                {
                    result[i] ^= roundKey[i];
                }

                byte[] temp = SHA512.HashData(result);
                Array.Copy(temp, result, Math.Min(temp.Length, result.Length));
            }

            return result;
        });
    }
}
