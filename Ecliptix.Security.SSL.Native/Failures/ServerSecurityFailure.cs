
namespace Ecliptix.Security.SSL.Native.Failures;

public sealed class ServerSecurityFailure
{
    public ServerSecurityFailureType Type { get; }
    public string Message { get; }
    public Exception? Exception { get; }

    private ServerSecurityFailure(ServerSecurityFailureType type, string message, Exception? exception = null)
    {
        Type = type;
        Message = message;
        Exception = exception;
    }

    public static ServerSecurityFailure ServiceNotInitialized() =>
        new(ServerSecurityFailureType.ServiceNotInitialized, "Server security service not initialized");

    public static ServerSecurityFailure ServiceDisposed() =>
        new(ServerSecurityFailureType.ServiceDisposed, "Server security service has been disposed");

    public static ServerSecurityFailure LibraryInitializationFailed(string error) =>
        new(ServerSecurityFailureType.LibraryInitializationFailed, $"Library initialization failed: {error}");

    public static ServerSecurityFailure InitializationException(Exception ex) =>
        new(ServerSecurityFailureType.InitializationException, "Initialization exception occurred", ex);

    public static ServerSecurityFailure PrivateKeyRequired() =>
        new(ServerSecurityFailureType.InvalidInput, "Private key is required");

    public static ServerSecurityFailure PublicKeyRequired() =>
        new(ServerSecurityFailureType.InvalidInput, "Public key is required");

    public static ServerSecurityFailure PlaintextRequired() =>
        new(ServerSecurityFailureType.InvalidInput, "Plaintext is required");

    public static ServerSecurityFailure CiphertextRequired() =>
        new(ServerSecurityFailureType.InvalidInput, "Ciphertext is required");

    public static ServerSecurityFailure DataRequired() =>
        new(ServerSecurityFailureType.InvalidInput, "Data is required");

    public static ServerSecurityFailure EncryptionFailed(string error) =>
        new(ServerSecurityFailureType.CryptographicFailure, $"Encryption failed: {error}");

    public static ServerSecurityFailure EncryptionException(Exception ex) =>
        new(ServerSecurityFailureType.CryptographicFailure, "Encryption exception occurred", ex);

    public static ServerSecurityFailure DecryptionFailed(string error) =>
        new(ServerSecurityFailureType.CryptographicFailure, $"Decryption failed: {error}");

    public static ServerSecurityFailure DecryptionException(Exception ex) =>
        new(ServerSecurityFailureType.CryptographicFailure, "Decryption exception occurred", ex);

    public static ServerSecurityFailure SigningFailed(string error) =>
        new(ServerSecurityFailureType.CryptographicFailure, $"Signing failed: {error}");

    public static ServerSecurityFailure SigningException(Exception ex) =>
        new(ServerSecurityFailureType.CryptographicFailure, "Signing exception occurred", ex);

    public static ServerSecurityFailure KeyGenerationFailed(string error) =>
        new(ServerSecurityFailureType.CryptographicFailure, $"Key generation failed: {error}");

    public static ServerSecurityFailure KeyGenerationException(Exception ex) =>
        new(ServerSecurityFailureType.CryptographicFailure, "Key generation exception occurred", ex);

    public static ServerSecurityFailure MessageRequired() =>
        new(ServerSecurityFailureType.InvalidInput, "Message is required");

    public static ServerSecurityFailure InvalidPrivateKey() =>
        new(ServerSecurityFailureType.InvalidInput, "Invalid private key format or size");

    public static ServerSecurityFailure InvalidPublicKey() =>
        new(ServerSecurityFailureType.InvalidInput, "Invalid public key format or size");

    public static ServerSecurityFailure InvalidSignature() =>
        new(ServerSecurityFailureType.InvalidInput, "Invalid signature format or size");

    public static ServerSecurityFailure VerificationException(Exception ex) =>
        new(ServerSecurityFailureType.CryptographicFailure, "Verification exception occurred", ex);

    public override string ToString() => Message;
}