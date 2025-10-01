namespace Ecliptix.Core.Infrastructure.Grpc.Constants;

public static class InterceptorConstants
{
    public static class Telemetry
    {
        public const string GrpcInterceptorsActivitySource = "Ecliptix.GrpcInterceptors";

        public const string GrpcTelemetryMeter = "Ecliptix.GrpcTelemetry";

        public const string ConnectionsMeter = "Ecliptix.Connections";
    }

    public static class Activities
    {
        public const string GrpcUnaryCall = "GrpcUnaryCall";

        public const string GrpcServerStreamingCall = "GrpcServerStreamingCall";
    }

    public static class Tags
    {
        public const string GrpcMethod = "grpc.method";
        public const string GrpcStatus = "grpc.status";
        public const string GrpcDurationMs = "grpc.duration_ms";
        public const string GrpcRequestSize = "grpc.request_size";
        public const string GrpcResponseSize = "grpc.response_size";
        public const string GrpcError = "grpc.error";
        public const string GrpcStreaming = "grpc.streaming";
        public const string GrpcMessagesSent = "grpc.messages_sent";

        public const string GrpcClientHash = "grpc.client_hash";
        public const string GrpcUserAgent = "grpc.user_agent";
    }

    public static class Headers
    {
        public const string ConnectIdKey = "connectid";
    }

    public static class StatusMessages
    {
        public const string Ok = "OK";

        public const string Internal = "INTERNAL";

        public const string TooManyRequests = "Too many requests";

        public const string InvalidConnectionIdentifier = "Invalid connection identifier";

        public const string InternalServerError = "Internal server error";

        public const string UnexpectedInternalServerError = "An unexpected internal server error occurred.";
    }

    public static class SecurityEvents
    {
        public const string RequestProcessed = "REQUEST_PROCESSED";

        public const string RequestCompleted = "REQUEST_COMPLETED";

        public const string RequestFailed = "REQUEST_FAILED";

        public const string RequestError = "REQUEST_ERROR";
    }

    public static class Connections
    {
        public const string UniqueConnectIdKey = "UniqueConnectId";

        public const string Unknown = "unknown";

        public const string Sanitized = "sanitized";

        public static class CloseReasons
        {
            public const string RequestCancelled = "Request cancelled";
            public const string StreamCancelled = "Stream cancelled";
            public const string StreamCompleted = "Stream completed";
            public const string StreamError = "Stream error: {0}";
        }
    }

    public static class Metrics
    {
        public const string GrpcRequestsTotal = "grpc_requests_total";

        public const string GrpcRequestsTotalDescription = "Total number of gRPC requests";

        public const string ConnectionsEstablishedTotal = "connections_established_total";

        public const string ConnectionsEstablishedTotalDescription = "Total number of connections established";

        public const string ConnectionsClosedTotal = "connections_closed_total";

        public const string ConnectionsClosedTotalDescription = "Total number of connections closed";

        public const string ActiveConnectionsCurrent = "active_connections_current";

        public const string ActiveConnectionsCurrentDescription = "Current number of active connections";
    }

    public static class Thresholds
    {
        public const int MinTimeBetweenRequestsMs = 1000;

        public const int LogThrottleIntervalSeconds = 10;

        public const int SlowRequestThresholdMs = 5000;

        public const int ConnectionMonitoringUpdateIntervalSeconds = 10;

        public const int CacheCleanupIntervalMinutes = 5;
    }

    public static class Limits
    {
        public const int MaxLastRequestTimesCount = 10000;

        public const int MaxLogTimesCount = 1000;

        public const int CleanupBatchSize = 100;

        public const int LargeCleanupBatchSize = 1000;

        public const int MaxUserAgentLength = 200;

        public const uint MinConnectId = 1;

        public const uint MaxConnectId = uint.MaxValue - 1000;

        public const int ConnectionLogFrequency = 10;
    }

    public static class LogPrefixes
    {
        public const string GrpcStart = "grpc_start_";

        public const string GrpcSuccess = "grpc_success_";
    }

    public static class Systems
    {
        public const string Grpc = "grpc";

        public const string SqlServer = "mssql";

        public const string Twilio = "twilio";
    }

    public static class LogMessages
    {
        public const string ConnectionTracked = "New connection tracked: {ConnectId} - Method: {Method}";
        public const string ConnectionActive = "Connection {ConnectId} active: {RequestCount} requests over {Duration:mm\\:ss}";
        public const string ConnectionError = "Connection {ConnectId} error #{ErrorCount}: {Error}";
        public const string ConnectionClosed = "Connection {ConnectId} closed after {Duration:mm\\:ss} - {RequestCount} requests, {ErrorCount} errors - Reason: {Reason}";

        public const string GrpcCallStart = "Starting gRPC call {Method}";
        public const string GrpcCallCompleted = "Completed gRPC call {Method} in {Duration}ms - Status: OK";
        public const string SlowGrpcCall = "Slow gRPC call detected: {Method} took {Duration}ms";
        public const string GrpcCallFailed = "gRPC call {Method} failed with {StatusCode} in {Duration}ms: {Message}";
        public const string GrpcCallUnexpectedError = "Unexpected error in gRPC call {Method} after {Duration}ms";
        public const string GrpcStreamingStart = "Starting gRPC streaming call {Method} from client {ClientHash}";
        public const string GrpcStreamingCompleted = "Completed gRPC streaming call {Method} in {Duration}ms from client {ClientHash} - Messages: {Count}";
        public const string GrpcStreamingError = "Error in gRPC streaming call {Method} after {Duration}ms from client {ClientHash}";

        public const string RequestTimingValidationFailed = "Request timing validation failed for {ClientIp} on {Method}";
        public const string ConnectIdValidationFailed = "ConnectId validation failed for {ClientIp} on {Method}";
        public const string UnexpectedSecurityError = "Unexpected error in security interceptor for {ClientIp} on {Method}";
        public const string InvalidConnectIdFormat = "Invalid ConnectId format: {ConnectId}";
        public const string ConnectIdOutOfRange = "ConnectId out of valid range: {ConnectId}";
        public const string ErrorValidatingConnectId = "Error validating ConnectId";
        public const string SecurityEvent = "Security Event: {EventType} | Method: {Method} | Client: {ClientIp} | UserAgent: {UserAgent}";

        public const string GrpcDomainFailure = "gRPC call {Method} terminated by a handled domain failure. Status: {StatusCode}. Details: {@LogPayload}";
        public const string GrpcPreExistingException = "gRPC call {Method} failed with a pre-existing RpcException. Status: {StatusCode}.";
        public const string GrpcUnhandledException = "An unhandled exception was thrown during gRPC call {Method}.";
    }

    public static class Formatting
    {
        public const string HashFormat = "X8";
    }

    public static class Characters
    {
        public const string Colon = ":";
        public const char Space = ' ';
    }

    public static class Numbers
    {
        public const int Zero = 0;
        public const int One = 1;
        public const int FirstIndex = 0;
    }
}