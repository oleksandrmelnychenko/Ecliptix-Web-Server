namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

public enum CertificatePinningResult
{
    Success = 0,
    InvalidParams = -1,
    CryptoFailure = -2,
    VerificationFailed = -3,
    InitFailed = -4
}
