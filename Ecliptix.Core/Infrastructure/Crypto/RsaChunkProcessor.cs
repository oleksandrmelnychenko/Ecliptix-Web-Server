using System.Buffers;
using System.Runtime.CompilerServices;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Infrastructure.Crypto;

public sealed class RsaChunkProcessor(
    IRsaConfiguration configuration,
    EcliptixCertificatePinningService certificatePinningService)
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

    private async ValueTask<Result<byte[], CertificatePinningFailure>> ProcessChunksAsync(
        ReadOnlyMemory<byte> input,
        int inputChunkSize,
        int maxOutputChunkSize,
        Func<ReadOnlyMemory<byte>, ValueTask<Result<byte[], CertificatePinningFailure>>> processor,
        CancellationToken cancellationToken)
    {
        int totalChunks = (input.Length + inputChunkSize - 1) / inputChunkSize;
        int estimatedOutputSize = totalChunks * maxOutputChunkSize;

        ArrayBufferWriter<byte> outputWriter = new(estimatedOutputSize);

        await foreach (ReadOnlyMemory<byte> chunk in GetChunksAsync(input, inputChunkSize, cancellationToken))
        {
            Result<byte[], CertificatePinningFailure> chunkResult = await processor(chunk);

            if (chunkResult.IsErr)
            {
                return chunkResult;
            }

            byte[] processedData = chunkResult.Unwrap();
            outputWriter.Write(processedData);

            cancellationToken.ThrowIfCancellationRequested();
        }

        return Result<byte[], CertificatePinningFailure>.Ok(outputWriter.WrittenMemory.ToArray());
    }

    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> GetChunksAsync(
        ReadOnlyMemory<byte> data,
        int chunkSize,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        for (int offset = 0; offset < data.Length; offset += chunkSize)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int currentChunkSize = Math.Min(chunkSize, data.Length - offset);
            ReadOnlyMemory<byte> chunk = data.Slice(offset, currentChunkSize);

            yield return chunk;

            await Task.Yield();
        }
    }

    private async ValueTask<Result<byte[], CertificatePinningFailure>> ProcessEncryptChunkAsync(
        ReadOnlyMemory<byte> chunk)
    {
        if (chunk.Length > configuration.OptimalChunkSize)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.EncryptionFailed(
                    $"Chunk size {chunk.Length} exceeds maximum {configuration.OptimalChunkSize}"));
        }

        return await certificatePinningService.EncryptAsync(chunk.ToArray());
    }

    private async ValueTask<Result<byte[], CertificatePinningFailure>> ProcessDecryptChunkAsync(
        ReadOnlyMemory<byte> chunk)
    {
        if (chunk.Length != configuration.EncryptedBlockSize)
        {
            return Result<byte[], CertificatePinningFailure>.Err(
                CertificatePinningFailure.DecryptionFailed(
                    $"Encrypted chunk size {chunk.Length} does not match expected {configuration.EncryptedBlockSize}"));
        }

        return await certificatePinningService.DecryptAsync(chunk.ToArray());
    }
}