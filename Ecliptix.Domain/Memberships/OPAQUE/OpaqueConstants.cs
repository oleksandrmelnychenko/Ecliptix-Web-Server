namespace Ecliptix.Domain.Memberships.OPAQUE;

public static class OpaqueConstants
{
    public static readonly byte[] OprfKeyInfo = "Ecliptix-OPAQUE-OPRFKey"u8.ToArray();
    public static readonly byte[] TokenKeyInfo = "Ecliptix-OPAQUE-TokenKey"u8.ToArray();
    public static readonly byte[] ServerStaticKeyInfo = "Ecliptix-OPAQUE-ServerStaticKey"u8.ToArray();
    public static readonly byte[] AkeSalt = "OPAQUE-AKE-Salt"u8.ToArray();
    public static readonly byte[] SessionKeyInfo = "session_key"u8.ToArray();
    public static readonly byte[] ClientMacKeyInfo = "client_mac_key"u8.ToArray();
    public static readonly byte[] ServerMacKeyInfo = "server_mac_key"u8.ToArray();

    public static readonly byte[] ProtocolVersion = "Ecliptix-OPAQUE-v1"u8.ToArray();

    public const int CompressedPublicKeyLength = 33;
    public const int DefaultKeyLength = 32;
    public const int MacKeyLength = 32;

    public const int AesGcmNonceLengthBytes = 12;
    public const int AesGcmTagLengthBits = 128;
}