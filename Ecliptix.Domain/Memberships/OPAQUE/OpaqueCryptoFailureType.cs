namespace Ecliptix.Domain.Memberships.OPAQUE;

public enum OpaqueCryptoFailureType
{
    HashingValidPointFailed,
    DecryptFailure,
    EncryptFailure,
    InvalidInput,
    HashingFailure,
    InvalidKeySignature,
    TokenExpired,
    CalculateRegistrationRecord
}