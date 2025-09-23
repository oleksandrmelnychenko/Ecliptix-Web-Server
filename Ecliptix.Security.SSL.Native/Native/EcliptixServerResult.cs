namespace Ecliptix.Security.SSL.Native.Native;

public enum EcliptixServerResult
{
    Success = 0,
    InvalidParams = -1,
    CryptoFailure = -2,
    VerificationFailed = -3,
    InitFailed = -4
}