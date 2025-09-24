namespace Ecliptix.Domain.Memberships.OPAQUE;

/// <summary>
/// Types of failures that can occur during OPAQUE cryptographic operations
/// </summary>
public enum OpaqueCryptoFailureType
{
    InvalidInput,
    CalculateRegistrationRecord,
    TokenExpired,
    InvalidKeySignature,
    DecryptFailure,
    EncryptFailure
}