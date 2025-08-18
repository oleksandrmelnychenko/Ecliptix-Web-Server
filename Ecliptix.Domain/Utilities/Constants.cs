namespace Ecliptix.Domain.Utilities;

public static class Constants
{
    public const int X25519KeySize = 32;
    public const uint CacheWindowSize = 1000;
    public const int Ed25519KeySize = 32;

    public const int Ed25519PublicKeySize = 32;
    public const int Ed25519SecretKeySize = 64;
    public const int Ed25519SignatureSize = 64;
    public const int X25519PublicKeySize = 32;
    public const int X25519PrivateKeySize = 32;
    public const int AesKeySize = 32;
    public const int AesGcmNonceSize = 12;
    public const int AesGcmTagSize = 16;

    public static readonly TimeSpan RotationTimeout = TimeSpan.FromSeconds(3600);

    // HKDF Info constants
    public static readonly byte[] MsgInfo = { 0x01 };
    public static readonly byte[] ChainInfo = { 0x02 };

    public static readonly byte[] DhRatchetInfo = { 0x03 }; // For Root Key + Chain Key derivation post-DH

    // Info constants for initial chain key derivation from root key
    // Ensure these are distinct from DhRatchetInfo and each other
    public static readonly byte[] InitialSenderChainInfo = { 0x11 };
    public static readonly byte[] InitialReceiverChainInfo = { 0x12 };
    public static ReadOnlySpan<byte> X3dhInfo => "Ecliptix_X3DH"u8;

    // Protocol configuration constants
    public const uint DefaultMaxSkippedMessages = 1000;
    public const uint DefaultMaxOutOfOrderWindow = 1000;
    public const uint MaxMessagesWithoutRatchetDefault = 1000;
    public const uint DefaultCacheWindowSize = 1000;
    public const uint NonceCounterWarningThreshold = 1000; // uint.MaxValue - 1000

    // Performance profiler formatting constants
    public const int OperationColumnWidth = 25;
    public const int CountColumnWidth = 8;
    public const int MetricsColumnWidth = 10;
    public const int TotalReportWidth = 63;
    public const string MetricsFormat = "F2";
    
    // Snapshot and persistence constants
    public const int SnapshotInterval = 50;
    public const int SnapshotModulus = 10;
    public const int SnapshotMinuteMultiplier = 5;
}