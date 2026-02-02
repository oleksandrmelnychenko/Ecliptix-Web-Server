using Ecliptix.Security.Opaque.Constants;

namespace Ecliptix.Security.Opaque.Failures;

public sealed class OpaqueRelayFailure
{
    public OpaqueRelayFailureType Type { get; }
    public string Message { get; }
    public Exception? Exception { get; }

    private OpaqueRelayFailure(OpaqueRelayFailureType type, string message, Exception? exception = null)
    {
        Type = type;
        Message = message;
        Exception = exception;
    }

    public static OpaqueRelayFailure ServiceNotInitialized() =>
        new(OpaqueRelayFailureType.ServiceNotInitialized, OpaqueRelayConstants.ErrorMessages.ServiceNotInitialized);

    public static OpaqueRelayFailure ServiceDisposed() =>
        new(OpaqueRelayFailureType.ServiceDisposed, OpaqueRelayConstants.ErrorMessages.ServiceDisposed);

    public static OpaqueRelayFailure LibraryInitializationFailed(string error) =>
        new(OpaqueRelayFailureType.LibraryInitializationFailed, $"OPAQUE library initialization failed: {error}");

    public static OpaqueRelayFailure InitializationException(Exception ex) =>
        new(OpaqueRelayFailureType.InitializationException, OpaqueRelayConstants.ErrorMessages.InitializationException, ex);

    public static OpaqueRelayFailure InvalidInput(string message) =>
        new(OpaqueRelayFailureType.InvalidInput, message);

    public static OpaqueRelayFailure RegistrationFailed(string error) =>
        new(OpaqueRelayFailureType.CryptographicFailure, $"Registration failed: {error}");

    public static OpaqueRelayFailure KeyExchangeFailed(string error) =>
        new(OpaqueRelayFailureType.CryptographicFailure, $"Key exchange failed: {error}");

    public static OpaqueRelayFailure AuthenticationFailed(string error) =>
        new(OpaqueRelayFailureType.CryptographicFailure, $"Authentication failed: {error}");

    public static OpaqueRelayFailure CredentialStorageFailed(string error) =>
        new(OpaqueRelayFailureType.StorageFailure, $"Credential storage failed: {error}");

    public static OpaqueRelayFailure CredentialRetrievalFailed(string error) =>
        new(OpaqueRelayFailureType.StorageFailure, $"Credential retrieval failed: {error}");

    public static OpaqueRelayFailure CryptographicException(Exception ex) =>
        new(OpaqueRelayFailureType.CryptographicFailure, OpaqueRelayConstants.ErrorMessages.CryptographicException, ex);

    public static OpaqueRelayFailure StorageException(Exception ex) =>
        new(OpaqueRelayFailureType.StorageFailure, OpaqueRelayConstants.ErrorMessages.StorageException, ex);

    public static OpaqueRelayFailure MemoryAllocationFailed(string message) =>
        new(OpaqueRelayFailureType.CryptographicFailure, $"Memory allocation failed: {message}");

    public static OpaqueRelayFailure MemoryWriteFailed(string message) =>
        new(OpaqueRelayFailureType.CryptographicFailure, $"Memory write failed: {message}");

    public override string ToString() => Message;
}
