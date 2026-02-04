namespace Ecliptix.Security.Certificate.Pinning.NativeResolver;

public static class CertificatePinningConfigurationConstants
{
    public const int MaxSignatureSize = 64;
    public const int MaxCiphertextSize = 256;
    public const int MaxPlaintextSize = 190;
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519PrivateKeySize = 32;
    public const int Ed25519SignatureSize = 64;

    public const int RsaKeySize = 2048;
    public const int RsaEncryptedBlockSize = 256;
    public const int RsaMaxPlaintextSize = 190;
    public const int RsaOptimalChunkSize = 180;
    public const int RsaPrivateKeyDerMaxSize = 1216;
    public const int RsaPublicKeyDerSize = 294;

    public static class ErrorMessages
    {
        public const string GenericError = "Error occurred";
    }
}
