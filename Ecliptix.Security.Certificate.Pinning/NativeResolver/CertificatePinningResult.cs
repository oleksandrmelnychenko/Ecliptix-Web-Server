namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

public enum CertificatePinningResult
{
    Success = 0,
    NotInitialized = -1,
    InvalidInput = -2,
    VerificationFailed = -3,
    EncryptionFailed = -4,
    DecryptionFailed = -5,
    BufferTooSmall = -6,
    InternalError = -7,
    InvalidKey = -8
}
