/*
 * Ecliptix Security SSL Native Library
 * Author: Oleksandr Melnychenko
 */

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
        new(ServerSecurityFailureType.InitializationException, "Exception during initialization", ex);

    public static ServerSecurityFailure PlaintextRequired() =>
        new(ServerSecurityFailureType.PlaintextRequired, "Plaintext data is required");

    public static ServerSecurityFailure PlaintextTooLarge() =>
        new(ServerSecurityFailureType.PlaintextTooLarge, "Plaintext data is too large for RSA encryption");

    public static ServerSecurityFailure PublicKeyRequired() =>
        new(ServerSecurityFailureType.PublicKeyRequired, "Public key is required for encryption");

    public static ServerSecurityFailure RsaEncryptionFailed(string error) =>
        new(ServerSecurityFailureType.RsaEncryptionFailed, $"RSA encryption failed: {error}");

    public static ServerSecurityFailure RsaEncryptionException(Exception ex) =>
        new(ServerSecurityFailureType.RsaEncryptionException, "Exception during RSA encryption", ex);

    public static ServerSecurityFailure CiphertextRequired() =>
        new(ServerSecurityFailureType.CiphertextRequired, "Ciphertext data is required");

    public static ServerSecurityFailure RsaDecryptionFailed(string error) =>
        new(ServerSecurityFailureType.RsaDecryptionFailed, $"RSA decryption failed: {error}");

    public static ServerSecurityFailure RsaDecryptionException(Exception ex) =>
        new(ServerSecurityFailureType.RsaDecryptionException, "Exception during RSA decryption", ex);

    public static ServerSecurityFailure MessageRequired() =>
        new(ServerSecurityFailureType.MessageRequired, "Message data is required for signing");

    public static ServerSecurityFailure Ed25519SigningFailed(string error) =>
        new(ServerSecurityFailureType.Ed25519SigningFailed, $"Ed25519 signing failed: {error}");

    public static ServerSecurityFailure Ed25519SigningException(Exception ex) =>
        new(ServerSecurityFailureType.Ed25519SigningException, "Exception during Ed25519 signing", ex);

    public static ServerSecurityFailure PrivateKeyLoadFailed(string error) =>
        new(ServerSecurityFailureType.PrivateKeyLoadFailed, $"Private key load failed: {error}");

    public static ServerSecurityFailure KeyLoadException(Exception ex) =>
        new(ServerSecurityFailureType.KeyLoadException, "Exception during private key loading", ex);

    public static ServerSecurityFailure LibraryCleanupError() =>
        new(ServerSecurityFailureType.LibraryCleanupError, "Error during library cleanup");

    public override string ToString() => Message;
}