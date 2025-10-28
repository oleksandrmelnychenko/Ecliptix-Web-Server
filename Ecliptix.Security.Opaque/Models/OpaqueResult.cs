namespace Ecliptix.Security.Opaque.Models;

public enum OpaqueResult
{
    Success = 0,
    InvalidInput = -1,
    CryptoError = -2,
    MemoryError = -3,
    ValidationError = -4,
    AuthenticationError = -5,
    InvalidPublicKey = -6
}
