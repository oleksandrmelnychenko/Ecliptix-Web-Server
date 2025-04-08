using Ecliptix.Protobuf.PubKeyExchange;

namespace Ecliptix.Core.Protocol;

/// <summary>
/// Interface for initiating and completing the X3DH handshake,
/// typically interacting with a central server or data center.
/// </summary>
public interface IDataCenterPubKeyExchange
{
    /// <summary>
    /// Starts the handshake process by generating local ephemeral keys and bundling public keys.
    /// </summary>
    /// <param name="exchangeType">The type/context of the key exchange.</param>
    /// <returns>A tuple containing the new Session ID and the initial PubKeyExchange message to send.</returns>
    /// <exception cref="ShieldChainStepException">Throws if setup fails (e.g., session type already exists).</exception>
    Task<(uint SessionId, PubKeyExchange InitialMessage)> BeginDataCenterPubKeyExchangeAsync(
        PubKeyExchangeOfType exchangeType);

    /// <summary>
    /// Completes the handshake using the peer's bundle, derives the shared secret (root key),
    /// and initializes the Double Ratchet chains.
    /// </summary>
    /// <param name="sessionId">The ID of the session being established.</param>
    /// <param name="exchangeType">The type/context of the key exchange.</param>
    /// <param name="peerMessage">The PubKeyExchange message received from the peer.</param>
    /// <returns>A tuple containing the Session ID and a secure handle to the derived root key. Caller MUST dispose the handle.</returns>
    /// <exception cref="ShieldChainStepException">Throws if handshake fails (e.g., invalid signature, key derivation error, session not found).</exception>
    Task<(uint SessionId, SodiumSecureMemoryHandle RootKeyHandle)> CompleteDataCenterPubKeyExchangeAsync(
        uint sessionId,
        PubKeyExchangeOfType exchangeType,
        PubKeyExchange peerMessage);

    // Note: rotate_dh_chain from Rust seems specific to reacting to a peer's key.
    // It's handled internally by ShieldSession.RotateReceiverKey now.
    // If explicit external rotation control is needed, this interface method could be kept,
    // but it might be redundant with the message processing flow. Let's omit for now.
    // Task<(uint SessionId, byte[]? OurNewPublicKey)> RotateDhChainAsync(
    //     uint sessionId, PubKeyExchangeOfType exchangeType, byte[] peerPublicKey, bool isSenderPerspective);
}