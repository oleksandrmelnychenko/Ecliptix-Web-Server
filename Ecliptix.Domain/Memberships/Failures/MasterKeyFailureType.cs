namespace Ecliptix.Domain.Memberships.Failures;

public enum MasterKeyFailureType : short
{
    InvalidThreshold,
    InvalidShareCount,
    InvalidKeyLength,
    InvalidKeyData,
    InvalidShareData,
    InvalidIdentifier,
    KeySplittingFailed,
    KeyReconstructionFailed,
    ShareValidationFailed,
    InsufficientShares,
    HmacKeyStorageFailed,
    HmacKeyMissing,
    HmacKeyRetrievalFailed,
    HmacKeyRemovalFailed,
    KeyDerivationFailed,
    AllocationFailed,
    MemoryReadFailed,
    MemoryWriteFailed,
    ValidationFailed,
    PersistorAccess,
    InternalError
}
