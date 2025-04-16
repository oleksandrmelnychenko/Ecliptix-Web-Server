namespace Ecliptix.Core.Protocol.Utilities;

public static class Constants
{
    public const int X25519KeySize = 32;
    public const uint CacheWindowSize = 1000;
    public static readonly TimeSpan RotationTimeout = TimeSpan.FromSeconds(3600);
    public const int Ed25519KeySize = 32;
    // HKDF Info constants
    public static readonly byte[] MsgInfo = { 0x01 };
    public static readonly byte[] ChainInfo = { 0x02 };
    public static readonly byte[] DhRatchetInfo = { 0x03 }; // For Root Key + Chain Key derivation post-DH

    // Info constants for initial chain key derivation from root key
    // Ensure these are distinct from DhRatchetInfo and each other
    public static readonly byte[] InitialSenderChainInfo = { 0x11 };
    public static readonly byte[] InitialReceiverChainInfo = { 0x12 };

    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SecretKeySize = 64;
    public const int Ed25519SignatureSize = 64;
    public const int X25519PublicKeySize = 32;
    public const int X25519PrivateKeySize = 32;
    public const int AesKeySize = 32;
    public const int AesGcmNonceSize = 12;
    public const int AesGcmTagSize = 16;
}