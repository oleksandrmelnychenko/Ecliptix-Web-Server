using Ecliptix.SecureProtocol.Domain.ProtocolNative;
using Ecliptix.SharedKernel;

namespace Ecliptix.SecureProtocol.Domain.Protocol;

/// <summary>
/// Provides access to the server's long-term protocol identity keys.
/// </summary>
public interface IProtocolKeyService
{
    /// <summary>
    /// Initializes the server identity from a seed. Must be called before accessing keys.
    /// </summary>
    Result<Unit, EcliptixProtocolFailure> Initialize(byte[] seed);

    /// <summary>
    /// Gets the server's ML-KEM-768 (Kyber) public key (1184 bytes).
    /// </summary>
    Result<byte[], EcliptixProtocolFailure> GetServerKyberPublicKey();

    /// <summary>
    /// Gets the server's Ed25519 public key (32 bytes).
    /// </summary>
    Result<byte[], EcliptixProtocolFailure> GetServerEd25519PublicKey();

    /// <summary>
    /// Gets the server's X25519 public key (32 bytes).
    /// </summary>
    Result<byte[], EcliptixProtocolFailure> GetServerX25519PublicKey();
}
