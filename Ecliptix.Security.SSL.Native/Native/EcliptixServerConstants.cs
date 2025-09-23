namespace Ecliptix.Security.SSL.Native.Native;

internal static class EcliptixServerConstants
{
    public const int MaxSignatureSize = 512;  
    public const int MaxCiphertextSize = 512;  
    public const int MaxPlaintextSize = 245;  
    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519PrivateKeySize = 32;
    public const int Ed25519SignatureSize = 64;
}