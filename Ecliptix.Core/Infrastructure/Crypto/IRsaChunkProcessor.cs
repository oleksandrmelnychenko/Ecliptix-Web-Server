using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Utilities;

namespace Ecliptix.Core.Infrastructure.Crypto;

public interface IRsaChunkProcessor
{
    ValueTask<Result<byte[], CertificatePinningFailure>> EncryptChunkedAsync(
        ReadOnlyMemory<byte> plaintext,
        CancellationToken cancellationToken = default);

    ValueTask<Result<byte[], CertificatePinningFailure>> DecryptChunkedAsync(
        ReadOnlyMemory<byte> ciphertext,
        CancellationToken cancellationToken = default);
}