using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol;

/// <summary>
/// Interface for decrypting inbound messages using the established session.
/// </summary>
public interface IInboundMessageService
{
    /// <summary>
    /// Decrypts an incoming CipherPayload using the appropriate session's Double Ratchet state.
    /// Handles advancing the receiver chain, processing potential DH rotations, and replay detection.
    /// </summary>
    /// <param name="sessionId">The ID of the session context.</param> // Added Session ID
    /// <param name="exchangeType">The type/context of the session.</param>
    /// <param name="cipherPayload">The incoming encrypted payload.</param>
    /// <returns>The decrypted plaintext data.</returns>
    /// <exception cref="ShieldChainStepException">Throws if session not found, decryption fails (bad MAC, replay, etc.).</exception>
    Task<byte[]> ProcessInboundMessageAsync(
        uint sessionId, // Added Session ID for lookup
        PubKeyExchangeType exchangeType,
        CipherPayload cipherPayload); // Use CipherPayload class
}