namespace Ecliptix.Core.Protocol.Utilities;

public static class Constants
{
    public const int X25519KeySize = 32;
    public const uint CacheWindowSize = 1000;
    public static readonly TimeSpan RotationTimeout = TimeSpan.FromSeconds(3600);
    public const int Ed25519KeySize = 32;
    public static ReadOnlySpan<byte> ChainInfo => [0x01];
    public static ReadOnlySpan<byte> MsgInfo => [0x02];
    // Use Sodium constants directly if possible
    public const int Ed25519SeedSize = 32; // Sodium.PublicKeyAuth.SeedBytes
    public const int Ed25519PublicKeySize = 32; // Sodium.PublicKeyAuth.PublicKeyBytes
    public const int Ed25519SecretKeySize = 64; // Sodium.PublicKeyAuth.SecretKeyBytes
    public const int Ed25519SignatureSize = 64; // Sodium.PublicKeyAuth.SignatureBytes
    public const int X25519PublicKeySize = 32; // Sodium.ScalarMult.Bytes
    public const int X25519PrivateKeySize = 32; // Sodium.ScalarMult.ScalarBytes
    
    // AEAD Constants (Using System.Security.Cryptography.AesGcm)
    public const int AesKeySize = 32; // AES-256 requires a 32-byte key
    public const int AesGcmNonceSize = 12; // Recommended nonce size for AesGcm
    public const int AesGcmTagSize = 16; // 128-bit tag is common (16 bytes)
}
