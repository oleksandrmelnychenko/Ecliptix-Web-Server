using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Certificate.Pinning.Crypto;

public sealed class RsaChunkProcessor(
    IRsaConfiguration configuration,
    CertificatePinningService certificatePinningService)
    : IRsaChunkProcessor
{
    private const int MaxChunkedInputBytes = 1024 * 1024;

    public ValueTask<Result<byte[], CertificatePinningFailure>> EncryptChunkedAsync(
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken = default)
    {
        if (plaintext.IsEmpty)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.PlaintextRequired()));
        }

        try
        {
            Result<byte[], CertificatePinningFailure> result = ProcessChunks(
                plaintext,
                configuration.OptimalChunkSize,
                configuration.EncryptedBlockSize,
                ProcessEncryptChunk,
                CertificatePinningFailure.EncryptionFailed,
                cancellationToken);

            return ValueTask.FromResult(result);
        }
        catch (Exception ex)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.EncryptionException(ex)));
        }
    }

    public ValueTask<Result<byte[], CertificatePinningFailure>> DecryptChunkedAsync(
        ReadOnlyMemory<byte> ciphertext,
        CancellationToken cancellationToken = default)
    {
        if (ciphertext.IsEmpty)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.CiphertextRequired()));
        }

        if (ciphertext.Length % configuration.EncryptedBlockSize != 0)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionFailed(
                    $"Ciphertext length {ciphertext.Length} is not a multiple of block size {configuration.EncryptedBlockSize}")));
        }

        try
        {
            Result<byte[], CertificatePinningFailure> result = ProcessChunks(
                ciphertext,
                configuration.EncryptedBlockSize,
                configuration.MaxPlaintextSize,
                ProcessDecryptChunk,
                CertificatePinningFailure.DecryptionFailed,
                cancellationToken);

            return ValueTask.FromResult(result);
        }
        catch (Exception ex)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionException(ex)));
        }
    }

    private Result<byte[], CertificatePinningFailure> ProcessEncryptChunk(
        ReadOnlyMemory<byte> chunk)
    {
        if (chunk.Length > configuration.OptimalChunkSize)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.EncryptionFailed(
                    $"Chunk size {chunk.Length} exceeds maximum {configuration.OptimalChunkSize}"));
        }

        return certificatePinningService.Encrypt(chunk);
    }

    private Result<byte[], CertificatePinningFailure> ProcessDecryptChunk(
        ReadOnlyMemory<byte> chunk)
    {
        if (chunk.Length != configuration.EncryptedBlockSize)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionFailed(
                    $"Encrypted chunk size {chunk.Length} does not match expected {configuration.EncryptedBlockSize}"));
        }

        return certificatePinningService.Decrypt(chunk);
    }

    private static Result<byte[], CertificatePinningFailure> ProcessChunks(
        ReadOnlyMemory<byte> input,
        int inputChunkSize,
        int maxOutputChunkSize,
        Func<ReadOnlyMemory<byte>, Result<byte[], CertificatePinningFailure>> processor,
        Func<string, CertificatePinningFailure> failureFactory,
        CancellationToken cancellationToken)
    {
        if (input.Length > MaxChunkedInputBytes)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                failureFactory($"Payload size {input.Length} exceeds maximum {MaxChunkedInputBytes} bytes"));
        }

        if (inputChunkSize <= 0 || maxOutputChunkSize <= 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                failureFactory("Invalid chunk size configuration"));
        }

        int totalChunks = (input.Length + inputChunkSize - 1) / inputChunkSize;
        long estimatedOutputSizeLong = (long)totalChunks * maxOutputChunkSize;
        if (estimatedOutputSizeLong <= 0 || estimatedOutputSizeLong > Array.MaxLength)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                failureFactory("Output size exceeds allowed limits"));
        }

        int estimatedOutputSize = (int)estimatedOutputSizeLong;

        byte[] outputBuffer = new byte[estimatedOutputSize];
        int outputOffset = 0;

        for (int offset = 0; offset < input.Length; offset += inputChunkSize)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int remaining = input.Length - offset;
            int size = Math.Min(inputChunkSize, remaining);
            ReadOnlyMemory<byte> chunk = input.Slice(offset, size);

            Result<byte[], CertificatePinningFailure> chunkResult = processor(chunk);

            if (chunkResult.IsErr)
            {
                return chunkResult;
            }

            byte[] chunkBytes = chunkResult.Unwrap();
            if (chunkBytes.Length > maxOutputChunkSize)
            {
                return Result<byte[], CertificatePinningFailure>.Err(
                    failureFactory($"Chunk output size {chunkBytes.Length} exceeds maximum {maxOutputChunkSize}"));
            }

            if (outputOffset > outputBuffer.Length - chunkBytes.Length)
            {
                return Result<byte[], CertificatePinningFailure>.Err(
                    failureFactory("Output buffer overflow"));
            }

            Buffer.BlockCopy(chunkBytes, 0, outputBuffer, outputOffset, chunkBytes.Length);
            outputOffset += chunkBytes.Length;
        }

        if (outputOffset == outputBuffer.Length)
        {
            return Result<byte[], CertificatePinningFailure>.Ok(outputBuffer);
        }

        byte[] result = new byte[outputOffset];
        Buffer.BlockCopy(outputBuffer, 0, result, 0, outputOffset);
        return Result<byte[], CertificatePinningFailure>.Ok(result);
    }
}
