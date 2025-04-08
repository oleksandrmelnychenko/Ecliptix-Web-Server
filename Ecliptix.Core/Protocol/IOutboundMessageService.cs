using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol;

/// <summary>
/// Interface for encrypting outbound messages using the established session.
/// </summary>
public interface IOutboundMessageService
{
    /// <summary>
    /// Encrypts plaintext using the appropriate session's Double Ratchet state.
    /// Handles advancing the sender chain and potentially performing DH rotations.
    /// </summary>
    /// <param name="sessionId">The ID of the session to use.</param>
    /// <param name="exchangeType">The type/context of the session.</param>
    /// <param name="plainPayload">The plaintext data to encrypt.</param>
    /// <returns>The resulting CipherPayload containing ciphertext and metadata.</returns>
    /// <exception cref="ShieldChainStepException">Throws if session not found, not ready, or encryption fails.</exception>
    Task<CipherPayload> ProduceOutboundMessageAsync(
        uint sessionId, // Added Session ID for lookup
        PubKeyExchangeOfType exchangeType,
        byte[] plainPayload); // Use byte[] for payload
}