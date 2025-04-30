namespace Ecliptix.Domain.Utilities;

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
    SessionExpired,
    DataAccessError
}