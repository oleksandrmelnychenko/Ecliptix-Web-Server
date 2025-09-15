namespace Ecliptix.Core.Domain.Protocol;

public static class ProtocolConstants
{
    public static class SodiumInterop
    {
        public const string LibSodiumName = "libsodium";
        public const int MaxBufferSize = 1_000_000_000;
        public const int SmallBufferThreshold = 64;
        public const int DllImportSuccess = 0;
    }

    public static class Security
    {
        public const int MinSecretKeySeedSizeBytes = 32;
    }

    public static class AdaptiveRatchet
    {
        public const int AnalysisIntervalSeconds = 10;
        public const int MessageWindowSizeMinutes = 1;
    }

    public static class Messages
    {
        public const string BufferNull = "Buffer cannot be null";
        public const string NotInitialized = "Sodium not initialized";
        public const string UnexpectedInitError = "Unexpected initialization error";
        public const string InitializationFailed = "Initialization failed";
        public const string SodiumInitFailed = "sodium_init returned error";
    }

    public static class ExceptionPatterns
    {
        public const string SodiumInitPattern = "sodium_init";
    }
}