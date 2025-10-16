using Ecliptix.Security.Opaque.Constants;

namespace Ecliptix.Security.Opaque.Failures;

public sealed class OpaqueServerFailure
{
    public OpaqueServerFailureType Type { get; }
    public string Message { get; }
    public Exception? Exception { get; }

    private OpaqueServerFailure(OpaqueServerFailureType type, string message, Exception? exception = null)
    {
        Type = type;
        Message = message;
        Exception = exception;
    }

    public static OpaqueServerFailure ServiceNotInitialized() =>
        new(OpaqueServerFailureType.ServiceNotInitialized, OpaqueServerConstants.ErrorMessages.ServiceNotInitialized);

    public static OpaqueServerFailure ServiceDisposed() =>
        new(OpaqueServerFailureType.ServiceDisposed, OpaqueServerConstants.ErrorMessages.ServiceDisposed);

    public static OpaqueServerFailure LibraryInitializationFailed(string error) =>
        new(OpaqueServerFailureType.LibraryInitializationFailed, $"OPAQUE library initialization failed: {error}");

    public static OpaqueServerFailure InitializationException(Exception ex) =>
        new(OpaqueServerFailureType.InitializationException, OpaqueServerConstants.ErrorMessages.InitializationException, ex);

    public static OpaqueServerFailure InvalidInput(string message) =>
        new(OpaqueServerFailureType.InvalidInput, message);

    public static OpaqueServerFailure RegistrationFailed(string error) =>
        new(OpaqueServerFailureType.CryptographicFailure, $"Registration failed: {error}");

    public static OpaqueServerFailure KeyExchangeFailed(string error) =>
        new(OpaqueServerFailureType.CryptographicFailure, $"Key exchange failed: {error}");

    public static OpaqueServerFailure AuthenticationFailed(string error) =>
        new(OpaqueServerFailureType.CryptographicFailure, $"Authentication failed: {error}");

    public static OpaqueServerFailure CredentialStorageFailed(string error) =>
        new(OpaqueServerFailureType.StorageFailure, $"Credential storage failed: {error}");

    public static OpaqueServerFailure CredentialRetrievalFailed(string error) =>
        new(OpaqueServerFailureType.StorageFailure, $"Credential retrieval failed: {error}");

    public static OpaqueServerFailure CryptographicException(Exception ex) =>
        new(OpaqueServerFailureType.CryptographicFailure, OpaqueServerConstants.ErrorMessages.CryptographicException, ex);

    public static OpaqueServerFailure StorageException(Exception ex) =>
        new(OpaqueServerFailureType.StorageFailure, OpaqueServerConstants.ErrorMessages.StorageException, ex);

    public static OpaqueServerFailure MemoryAllocationFailed(string message) =>
        new(OpaqueServerFailureType.CryptographicFailure, $"Memory allocation failed: {message}");

    public static OpaqueServerFailure MemoryWriteFailed(string message) =>
        new(OpaqueServerFailureType.CryptographicFailure, $"Memory write failed: {message}");

    public override string ToString() => Message;
}