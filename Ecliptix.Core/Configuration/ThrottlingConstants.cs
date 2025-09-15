namespace Ecliptix.Core.Configuration;

public static class ThrottlingConstants
{
    public const int MaxRequestsPerMinute = 60;
    public const int MaxFailuresBeforeBlock = 5;
    public const int BlockDurationMinutes = 15;
    public const int CleanupIntervalMinutes = 5;
    public const string RetryAfterBlocked = "900";
    public const string RetryAfterRateLimit = "60";
    public const int CleanupInactiveEntriesAfterMinutes = 30;
    public const int MaxCleanupBatchSize = 1000;

    public static class CacheKeys
    {
        public const string BlockedIpPrefix = "blocked_ip:";
    }

    public static class Messages
    {
        public const string TooManyFailedRequests = "Too many failed requests";
        public const string IpTemporarilyBlocked = "IP temporarily blocked";
        public const string RateLimitExceeded = "Rate limit exceeded";
        public const string IpBlocked = "IP address {IpAddress} blocked for {Duration} minutes due to {Reason}";
        public const string BlockedRequest = "Blocked request from {IpAddress}";
        public const string RateLimitExceededLog = "Rate limit exceeded for {IpAddress}";
        public const string CleanupEntries = "Cleaned up {Count} old throttle entries";
    }
}