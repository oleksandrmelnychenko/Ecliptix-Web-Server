namespace Ecliptix.Security.Opaque.Failures;

public enum OpaqueRelayFailureType
{
    ServiceNotInitialized,
    ServiceDisposed,
    LibraryInitializationFailed,
    InitializationException,
    InvalidInput,
    CryptographicFailure,
    StorageFailure
}
