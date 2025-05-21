namespace Ecliptix.Domain.Utilities;

// Ecliptix.Domain.Utilities
public enum ShieldFailureType
{
    Generic,
    DecodeFailed,
    EphemeralMissing,
    ConversionFailed,
    PrepareLocalFailed,
    StateMissing,
    DeriveKeyFailed,
    PeerPubKeyFailed,
    PeerExchangeFailed,
    KeyRotationFailed,
    HandshakeFailed,
    DecryptFailed,
    StoreOpFailed,
    InvalidKeySize,
    InvalidEd25519Key,
    SpkVerificationFailed,
    HkdfInfoEmpty,
    KeyGenerationFailed,
    EncryptionFailed,
    InvalidInput,
    ObjectDisposed,
    AllocationFailed,
    PinningFailure,
    BufferTooSmall,
    DataTooLarge,
    DataAccessError,
    SessionExpired, // Added from your factory methods

    // PasswordManager specific types - we can add these here or map existing ones
    PasswordConfigInvalid,
    PasswordValidationFailed,
    PasswordHashingFailed,
    PasswordVerificationFailed,
    AuthenticationFailed
}