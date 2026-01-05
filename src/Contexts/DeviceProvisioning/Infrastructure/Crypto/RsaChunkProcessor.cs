using System.Runtime.CompilerServices;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.SharedKernel;

namespace Ecliptix.DeviceProvisioning.Infrastructure.Crypto;

public sealed class RsaChunkProcessor(
    IRsaConfiguration configuration,
    CertificatePinningService certificatePinningService)
    : IRsaChunkProcessor
{
    public async ValueTask<Result<byte[], CertificatePinningFailure>> EncryptChunkedAsync(
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken = default)
    {
        if (plaintext.IsEmpty)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.PlaintextRequired());
        }

        try
        {
            Result<byte[], CertificatePinningFailure> result = await ProcessChunksAsync(
                plaintext,
                configuration.OptimalChunkSize,
                configuration.EncryptedBlockSize,
                ProcessEncryptChunkAsync,
                cancellationToken);

            return result;
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.EncryptionException(ex));
        }
    }

    public async ValueTask<Result<byte[], CertificatePinningFailure>> DecryptChunkedAsync(
        ReadOnlyMemory<byte> ciphertext,
        CancellationToken cancellationToken = default)
    {
        if (ciphertext.IsEmpty)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.CiphertextRequired());
        }

        if (ciphertext.Length % configuration.EncryptedBlockSize != 0)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionFailed(
                    $"Ciphertext length {ciphertext.Length} is not a multiple of block size {configuration.EncryptedBlockSize}"));
        }

        try
        {
            Result<byte[], CertificatePinningFailure> result = await ProcessChunksAsync(
                ciphertext,
                configuration.EncryptedBlockSize,
                configuration.MaxPlaintextSize,
                ProcessDecryptChunkAsync,
                cancellationToken);

            return result;
        }
        catch (Exception ex)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionException(ex));
        }
    }

    private ValueTask<Result<byte[], CertificatePinningFailure>> ProcessEncryptChunkAsync(
        ReadOnlyMemory<byte> chunk)
    {
        if (chunk.Length > configuration.OptimalChunkSize)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.EncryptionFailed(
                    $"Chunk size {chunk.Length} exceeds maximum {configuration.OptimalChunkSize}")));
        }

        return ValueTask.FromResult(certificatePinningService.Encrypt(chunk));
    }

    private ValueTask<Result<byte[], CertificatePinningFailure>> ProcessDecryptChunkAsync(
        ReadOnlyMemory<byte> chunk)
    {
        if (chunk.Length != configuration.EncryptedBlockSize)
        {
            return ValueTask.FromResult(Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionFailed(
                    $"Encrypted chunk size {chunk.Length} does not match expected {configuration.EncryptedBlockSize}")));
        }

        return ValueTask.FromResult(certificatePinningService.Decrypt(chunk));
    }

    private static async ValueTask<Result<byte[], CertificatePinningFailure>> ProcessChunksAsync(
        ReadOnlyMemory<byte> input,
        int inputChunkSize,
        int maxOutputChunkSize,
        Func<ReadOnlyMemory<byte>, ValueTask<Result<byte[], CertificatePinningFailure>>> processor,
        CancellationToken cancellationToken)
    {
        int totalChunks = (input.Length + inputChunkSize - 1) / inputChunkSize;
        int estimatedOutputSize = totalChunks * maxOutputChunkSize;

        byte[] outputBuffer = new byte[estimatedOutputSize];
        int outputOffset = 0;

        await foreach (ReadOnlyMemory<byte> chunk in GetChunksAsync(input, inputChunkSize, cancellationToken))
        {
            Result<byte[], CertificatePinningFailure> chunkResult = await processor(chunk);

            if (chunkResult.IsErr)
            {
                return chunkResult;
            }

            byte[] chunkBytes = chunkResult.Unwrap();
            Buffer.BlockCopy(chunkBytes, 0, outputBuffer, outputOffset, chunkBytes.Length);
            outputOffset += chunkBytes.Length;
        }

        return Result<byte[], CertificatePinningFailure>.Ok(outputBuffer.AsSpan(0, outputOffset).ToArray());
    }

    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> GetChunksAsync(
        ReadOnlyMemory<byte> input,
        int chunkSize,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < input.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int remaining = input.Length - offset;
            int size = Math.Min(chunkSize, remaining);

            yield return input.Slice(offset, size);
            offset += size;
        }

        await Task.CompletedTask;
    }
}
