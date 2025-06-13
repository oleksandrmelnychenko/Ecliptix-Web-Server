namespace Ecliptix.Domain.Utilities;

public static class Constants
{
    public const int X25519KeySize = 32;
    public const int Ed25519KeySize = 32;

    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SecretKeySize = 64;
    public const int Ed25519SignatureSize = 64;
    public const int X25519PublicKeySize = 32;
    public const int X25519PrivateKeySize = 32;
    public const int AesKeySize = 32;
    public const int AesGcmNonceSize = 12;
    public const int AesGcmTagSize = 16;

    public static readonly byte[] MsgInfo = [0x01];
    public static readonly byte[] ChainInfo = [0x02];

    public static readonly byte[] X3dhInfo =
    [
        0x45, 0x63, 0x6C, 0x69, 0x70, 0x74, 0x69, 0x78, 0x5F, 0x58, 0x33, 0x44, 0x48
    ];
}