namespace Ecliptix.Security.Opaque.Failures;

public enum OpaqueServerFailureType
{
    ServiceNotInitialized,
    ServiceDisposed,
    LibraryInitializationFailed,
    InitializationException,
    InvalidInput,
    CryptographicFailure,
    StorageFailure
}