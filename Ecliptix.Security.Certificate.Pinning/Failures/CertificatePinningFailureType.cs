
namespace Ecliptix.Security.Certificate.Pinning.Failures;

public enum CertificatePinningFailureType
{
    ServiceNotInitialized,
    ServiceDisposed,
    LibraryInitializationFailed,
    InitializationException,
    InvalidInput,
    CryptographicFailure
}