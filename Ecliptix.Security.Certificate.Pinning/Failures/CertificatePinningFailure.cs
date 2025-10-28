
namespace Ecliptix.Security.Certificate.Pinning.Failures;

public sealed class CertificatePinningFailure
{
    public CertificatePinningFailureType Type { get; }
    public string Message { get; }
    public Exception? Exception { get; }

    private CertificatePinningFailure(CertificatePinningFailureType type, string message, Exception? exception = null)
    {
        Type = type;
        Message = message;
        Exception = exception;
    }

    public static CertificatePinningFailure ServiceNotInitialized() =>
        new(CertificatePinningFailureType.ServiceNotInitialized, "Server security service not initialized");

    public static CertificatePinningFailure ServiceDisposed() =>
        new(CertificatePinningFailureType.ServiceDisposed, "Server security service has been disposed");

    public static CertificatePinningFailure LibraryInitializationFailed(string error) =>
        new(CertificatePinningFailureType.LibraryInitializationFailed, $"Library initialization failed: {error}");

    public static CertificatePinningFailure InitializationException(Exception ex) =>
        new(CertificatePinningFailureType.InitializationException, "Initialization exception occurred", ex);

    public static CertificatePinningFailure PrivateKeyRequired() =>
        new(CertificatePinningFailureType.InvalidInput, "Private key is required");

    public static CertificatePinningFailure PublicKeyRequired() =>
        new(CertificatePinningFailureType.InvalidInput, "Public key is required");

    public static CertificatePinningFailure PlaintextRequired() =>
        new(CertificatePinningFailureType.InvalidInput, "Plaintext is required");

    public static CertificatePinningFailure CiphertextRequired() =>
        new(CertificatePinningFailureType.InvalidInput, "Ciphertext is required");

    public static CertificatePinningFailure DataRequired() =>
        new(CertificatePinningFailureType.InvalidInput, "Data is required");

    public static CertificatePinningFailure EncryptionFailed(string error) =>
        new(CertificatePinningFailureType.CryptographicFailure, $"Encryption failed: {error}");

    public static CertificatePinningFailure EncryptionException(Exception ex) =>
        new(CertificatePinningFailureType.CryptographicFailure, "Encryption exception occurred", ex);

    public static CertificatePinningFailure DecryptionFailed(string error) =>
        new(CertificatePinningFailureType.CryptographicFailure, $"Decryption failed: {error}");

    public static CertificatePinningFailure DecryptionException(Exception ex) =>
        new(CertificatePinningFailureType.CryptographicFailure, "Decryption exception occurred", ex);

    public static CertificatePinningFailure SigningFailed(string error) =>
        new(CertificatePinningFailureType.CryptographicFailure, $"Signing failed: {error}");

    public static CertificatePinningFailure SigningException(Exception ex) =>
        new(CertificatePinningFailureType.CryptographicFailure, "Signing exception occurred", ex);

    public static CertificatePinningFailure KeyGenerationFailed(string error) =>
        new(CertificatePinningFailureType.CryptographicFailure, $"Key generation failed: {error}");

    public static CertificatePinningFailure KeyGenerationException(Exception ex) =>
        new(CertificatePinningFailureType.CryptographicFailure, "Key generation exception occurred", ex);

    public static CertificatePinningFailure MessageRequired() =>
        new(CertificatePinningFailureType.InvalidInput, "Message is required");

    public static CertificatePinningFailure InvalidPrivateKey() =>
        new(CertificatePinningFailureType.InvalidInput, "Invalid private key format or size");

    public static CertificatePinningFailure InvalidPublicKey() =>
        new(CertificatePinningFailureType.InvalidInput, "Invalid public key format or size");

    public static CertificatePinningFailure InvalidSignature() =>
        new(CertificatePinningFailureType.InvalidInput, "Invalid signature format or size");

    public static CertificatePinningFailure VerificationException(Exception ex) =>
        new(CertificatePinningFailureType.CryptographicFailure, "Verification exception occurred", ex);

    public override string ToString() => Message;
}
