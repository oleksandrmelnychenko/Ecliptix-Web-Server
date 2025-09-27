namespace Ecliptix.Security.Opaque.Models;
public enum OpaqueCryptoFailureType
{
    InvalidInput,
    CalculateRegistrationRecord,
    TokenExpired,
    InvalidKeySignature,
    DecryptFailure,
    EncryptFailure
}