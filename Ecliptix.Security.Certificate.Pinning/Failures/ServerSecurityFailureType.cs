
namespace Ecliptix.Security.Certificate.Pinning.Failures;

public enum ServerSecurityFailureType
{
    ServiceNotInitialized,
    ServiceDisposed,
    LibraryInitializationFailed,
    InitializationException,
    InvalidInput,
    CryptographicFailure
}