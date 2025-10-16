namespace Ecliptix.Utilities;

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

    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8;

    public const uint DefaultMaxSkippedMessages = 1000;
    public const uint DefaultMaxOutOfOrderWindow = 1000;
    public const uint MaxMessagesWithoutRatchetDefault = 1000;
    public const uint DefaultCacheWindowSize = 1000;

    public const int OperationColumnWidth = 25;
    public const int CountColumnWidth = 8;
    public const int MetricsColumnWidth = 10;
    public const int TotalReportWidth = 63;
    public const string MetricsFormat = "F2";

    public const int Curve25519FieldElementSize = 32;
    public const int Field256WordCount = 8;
    public const int WordSize = 4;
    public const uint FieldElementMask = 0x7FFFFFFF;
}