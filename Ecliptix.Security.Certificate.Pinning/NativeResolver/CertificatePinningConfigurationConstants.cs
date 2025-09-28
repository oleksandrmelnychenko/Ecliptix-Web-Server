namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

public static class CertificatePinningConfigurationConstants
{
    public const int MaxSignatureSize = 512;
    public const int MaxCiphertextSize = 256;
    public const int MaxPlaintextSize = 256;
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519PrivateKeySize = 32;
    public const int Ed25519SignatureSize = 64;

    // RSA Configuration Constants
    public const int RsaKeySize = 2048;
    public const int RsaEncryptedBlockSize = 256;  // RSA-2048 output size
    public const int RsaMaxPlaintextSize = 214;     // RSA-2048 with OAEP padding
    public const int RsaOptimalChunkSize = 200;     // Optimal chunk size with safety margin
}