namespace Ecliptix.Core.Protocol.Utilities;

/// <summary>
/// Defines categories for failures within the Shield protocol layer.
/// </summary>
public enum ShieldFailureType
{
    Generic,             // Default or uncategorized
    DecodeFailed,        // Error during deserialization or key import
    EphemeralMissing,    // Expected ephemeral key was missing during an operation
    ConversionFailed,    // Failed converting between data types (e.g., bytes to array)
    PrepareLocalFailed,  // Error setting up local state before exchange
    StateMissing,        // Required session state or key material not found or invalid
    DeriveKeyFailed,     // Error during HKDF or DH calculation
    PeerPubKeyFailed,    // Error related to processing/importing peer's public key
    PeerExchangeFailed,  // Error decoding peer's exchange payload
    KeyRotationFailed,   // Error during SPK rotation, OPK replenishment, or ratchet step
    HandshakeFailed,     // Error during key exchange logic (e.g., signature validation)
    DecryptFailed,       // Error during decryption (incl. MAC failure, replay)
    StoreOpFailed,       // Failure interacting with persistent storage (if applicable)
    InvalidKeySize,      // Specific: Key data has wrong size (often leads to DecodeFailed)
    InvalidEd25519Key,   // Specific: Ed25519 key data is invalid (often leads to DecodeFailed)
    SpkVerificationFailed,// Specific: SPK signature verification failed (often leads to HandshakeFailed)
    HkdfInfoEmpty,       // Specific: HKDF 'info' parameter was empty (leads to DeriveKeyFailed)
    KeyGenerationFailed, // Error during initial key generation or ephemeral generation
    EncryptionFailed     // Added for completeness if encryption step can fail operationally
}