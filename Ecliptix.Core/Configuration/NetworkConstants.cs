namespace Ecliptix.Core.Configuration;

public static class NetworkConstants
{
    public static class Ports
    {
        public const int Grpc = 5051;
        public const int Http = 8080;
    }

    public static class Limits
    {
        public const int MaxConcurrentConnections = 1000;
        public const int MaxConcurrentUpgradedConnections = 1000;
        public const long MaxRequestBodySizeBytes = 10 * 1024 * 1024;
    }

    public static class RateLimit
    {
        public const int PermitLimit = 100;
        public const int WindowMinutes = 1;
        public const int SegmentsPerWindow = 4;
        public const int QueueLimit = 10;
    }

    public static class Compression
    {
        public const string Algorithm = "gzip";
    }
}