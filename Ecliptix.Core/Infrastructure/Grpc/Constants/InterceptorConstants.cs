namespace Ecliptix.Core.Infrastructure.Grpc.Constants;

/// <summary>
/// Centralized constants for gRPC interceptors to eliminate magic strings
/// </summary>
public static class InterceptorConstants
{
    /// <summary>
    /// Activity source and meter names for telemetry
    /// </summary>
    public static class Telemetry
    {
        /// <summary>
        /// Activity source name for gRPC interceptors
        /// </summary>
        public const string GrpcInterceptorsActivitySource = "Ecliptix.GrpcInterceptors";

        /// <summary>
        /// Meter name for gRPC telemetry
        /// </summary>
        public const string GrpcTelemetryMeter = "Ecliptix.GrpcTelemetry";

        /// <summary>
        /// Meter name for connections
        /// </summary>
        public const string ConnectionsMeter = "Ecliptix.Connections";
    }

    /// <summary>
    /// Activity names for different operations
    /// </summary>
    public static class Activities
    {
        /// <summary>
        /// Activity name for unary gRPC calls
        /// </summary>
        public const string GrpcUnaryCall = "GrpcUnaryCall";

        /// <summary>
        /// Activity name for server streaming gRPC calls
        /// </summary>
        public const string GrpcServerStreamingCall = "GrpcServerStreamingCall";

        /// <summary>
        /// Activity name for request decryption
        /// </summary>
        public const string DecryptRequest = "DecryptRequest";

        /// <summary>
        /// Activity name for response encryption
        /// </summary>
        public const string EncryptResponse = "EncryptResponse";

        /// <summary>
        /// Activity name for failure response creation
        /// </summary>
        public const string CreateFailureResponse = "CreateFailureResponse";
    }

    /// <summary>
    /// Activity tag names for telemetry
    /// </summary>
    public static class Tags
    {
        // gRPC related tags
        public const string GrpcMethod = "grpc.method";
        public const string GrpcStatus = "grpc.status";
        public const string GrpcDurationMs = "grpc.duration_ms";
        public const string GrpcRequestSize = "grpc.request_size";
        public const string GrpcResponseSize = "grpc.response_size";
        public const string GrpcError = "grpc.error";
        public const string GrpcStreaming = "grpc.streaming";
        public const string GrpcMessagesSent = "grpc.messages_sent";

        // Client identification tags
        public const string GrpcClientHash = "grpc.client_hash";
        public const string GrpcUserAgent = "grpc.user_agent";

        // Connection tags
        public const string ConnectId = "connect_id";
        public const string PayloadSize = "payload_size";
        public const string DecryptSuccess = "decrypt_success";
        public const string DecryptedSize = "decrypted_size";
        public const string EncryptSuccess = "encrypt_success";
        public const string EncryptedSize = "encrypted_size";
        public const string FailureType = "failure_type";

        // Service tags
        public const string ServiceName = "service.name";
        public const string RpcMethod = "rpc.method";
        public const string RpcSystem = "rpc.system";
        public const string EcliptixConnectId = "ecliptix.connect_id";

        // Actor tags
        public const string ActorType = "actor.type";
        public const string ActorOperation = "actor.operation";

        // Database tags
        public const string DbSystem = "db.system";
        public const string DbOperation = "db.operation";
        public const string DbTable = "db.table";

        // Messaging tags
        public const string MessagingSystem = "messaging.system";
        public const string MessagingOperation = "messaging.operation";
    }

    /// <summary>
    /// HTTP header names and related constants
    /// </summary>
    public static class Headers
    {
        /// <summary>
        /// Connect ID header key (case insensitive search)
        /// </summary>
        public const string ConnectIdKey = "connectid";

        /// <summary>
        /// User-Agent header
        /// </summary>
        public const string UserAgent = "User-Agent";
    }

    /// <summary>
    /// Status codes and messages
    /// </summary>
    public static class StatusMessages
    {
        /// <summary>
        /// Generic OK status
        /// </summary>
        public const string Ok = "OK";

        /// <summary>
        /// Internal error status
        /// </summary>
        public const string Internal = "INTERNAL";

        /// <summary>
        /// Rate limiting error message
        /// </summary>
        public const string TooManyRequests = "Too many requests";

        /// <summary>
        /// Invalid connection identifier error message
        /// </summary>
        public const string InvalidConnectionIdentifier = "Invalid connection identifier";

        /// <summary>
        /// Internal server error message
        /// </summary>
        public const string InternalServerError = "Internal server error";

        /// <summary>
        /// Unexpected internal server error message
        /// </summary>
        public const string UnexpectedInternalServerError = "An unexpected internal server error occurred.";
    }

    /// <summary>
    /// Security event types
    /// </summary>
    public static class SecurityEvents
    {
        /// <summary>
        /// Request processed successfully
        /// </summary>
        public const string RequestProcessed = "REQUEST_PROCESSED";

        /// <summary>
        /// Request completed successfully
        /// </summary>
        public const string RequestCompleted = "REQUEST_COMPLETED";

        /// <summary>
        /// Request failed
        /// </summary>
        public const string RequestFailed = "REQUEST_FAILED";

        /// <summary>
        /// Request error occurred
        /// </summary>
        public const string RequestError = "REQUEST_ERROR";
    }

    /// <summary>
    /// Connection-related constants
    /// </summary>
    public static class Connections
    {
        /// <summary>
        /// UserState key for unique connect ID
        /// </summary>
        public const string UniqueConnectIdKey = "UniqueConnectId";

        /// <summary>
        /// Default value for unknown client information
        /// </summary>
        public const string Unknown = "unknown";

        /// <summary>
        /// Default value for sanitized user agent
        /// </summary>
        public const string Sanitized = "sanitized";

        /// <summary>
        /// Connection closed reasons
        /// </summary>
        public static class CloseReasons
        {
            public const string RequestCancelled = "Request cancelled";
            public const string StreamCancelled = "Stream cancelled";
            public const string StreamCompleted = "Stream completed";
            public const string StreamError = "Stream error: {0}";
        }
    }

    /// <summary>
    /// Counter and gauge names for metrics
    /// </summary>
    public static class Metrics
    {
        /// <summary>
        /// Total gRPC requests counter
        /// </summary>
        public const string GrpcRequestsTotal = "grpc_requests_total";

        /// <summary>
        /// Description for gRPC requests counter
        /// </summary>
        public const string GrpcRequestsTotalDescription = "Total number of gRPC requests";

        /// <summary>
        /// Total connections established counter
        /// </summary>
        public const string ConnectionsEstablishedTotal = "connections_established_total";

        /// <summary>
        /// Description for connections established counter
        /// </summary>
        public const string ConnectionsEstablishedTotalDescription = "Total number of connections established";

        /// <summary>
        /// Total connections closed counter
        /// </summary>
        public const string ConnectionsClosedTotal = "connections_closed_total";

        /// <summary>
        /// Description for connections closed counter
        /// </summary>
        public const string ConnectionsClosedTotalDescription = "Total number of connections closed";

        /// <summary>
        /// Current active connections gauge
        /// </summary>
        public const string ActiveConnectionsCurrent = "active_connections_current";

        /// <summary>
        /// Description for active connections gauge
        /// </summary>
        public const string ActiveConnectionsCurrentDescription = "Current number of active connections";
    }

    /// <summary>
    /// Time thresholds and intervals
    /// </summary>
    public static class Thresholds
    {
        /// <summary>
        /// Minimum time between requests in milliseconds
        /// </summary>
        public const int MinTimeBetweenRequestsMs = 100;

        /// <summary>
        /// Log throttle interval in seconds
        /// </summary>
        public const int LogThrottleIntervalSeconds = 10;

        /// <summary>
        /// Slow request threshold in milliseconds
        /// </summary>
        public const int SlowRequestThresholdMs = 5000;

        /// <summary>
        /// Connection monitoring update interval in seconds
        /// </summary>
        public const int ConnectionMonitoringUpdateIntervalSeconds = 10;

        /// <summary>
        /// Cache cleanup interval in minutes
        /// </summary>
        public const int CacheCleanupIntervalMinutes = 5;
    }

    /// <summary>
    /// Size and count limits
    /// </summary>
    public static class Limits
    {
        /// <summary>
        /// Maximum number of last request times to keep
        /// </summary>
        public const int MaxLastRequestTimesCount = 10000;

        /// <summary>
        /// Maximum number of log times to keep
        /// </summary>
        public const int MaxLogTimesCount = 1000;

        /// <summary>
        /// Cleanup batch size
        /// </summary>
        public const int CleanupBatchSize = 100;

        /// <summary>
        /// Cleanup batch size for large collections
        /// </summary>
        public const int LargeCleanupBatchSize = 1000;

        /// <summary>
        /// Maximum user agent length
        /// </summary>
        public const int MaxUserAgentLength = 200;

        /// <summary>
        /// Minimum connect ID value
        /// </summary>
        public const uint MinConnectId = 1;

        /// <summary>
        /// Maximum connect ID value (with buffer)
        /// </summary>
        public const uint MaxConnectId = uint.MaxValue - 1000;

        /// <summary>
        /// Log frequency for connection activity (every N requests)
        /// </summary>
        public const int ConnectionLogFrequency = 10;
    }

    /// <summary>
    /// Log message prefixes for rate limiting
    /// </summary>
    public static class LogPrefixes
    {
        /// <summary>
        /// gRPC start prefix
        /// </summary>
        public const string GrpcStart = "grpc_start_";

        /// <summary>
        /// gRPC success prefix
        /// </summary>
        public const string GrpcSuccess = "grpc_success_";
    }

    /// <summary>
    /// System values and defaults
    /// </summary>
    public static class Systems
    {
        /// <summary>
        /// gRPC system identifier
        /// </summary>
        public const string Grpc = "grpc";

        /// <summary>
        /// SQL Server database system
        /// </summary>
        public const string SqlServer = "mssql";

        /// <summary>
        /// Twilio messaging system
        /// </summary>
        public const string Twilio = "twilio";
    }
}