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

        public const string DecryptRequest = "DecryptRequest";

        public const string EncryptResponse = "EncryptResponse";

        public const string CreateFailureResponse = "CreateFailureResponse";
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

        public const string ConnectId = "connect_id";
        public const string PayloadSize = "payload_size";
        public const string DecryptSuccess = "decrypt_success";
        public const string DecryptedSize = "decrypted_size";
        public const string EncryptSuccess = "encrypt_success";
        public const string EncryptedSize = "encrypted_size";
        public const string FailureType = "failure_type";

        public const string ServiceName = "service.name";
        public const string RpcMethod = "rpc.method";
        public const string RpcSystem = "rpc.system";
        public const string EcliptixConnectId = "ecliptix.connect_id";

        public const string ActorType = "actor.type";
        public const string ActorOperation = "actor.operation";

        public const string DbSystem = "db.system";
        public const string DbOperation = "db.operation";
        public const string DbTable = "db.table";

        public const string MessagingSystem = "messaging.system";
        public const string MessagingOperation = "messaging.operation";
    }

    public static class Headers
    {
        public const string ConnectIdKey = "connectid";

        public const string UserAgent = "User-Agent";
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
        public const int MinTimeBetweenRequestsMs = 100;

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
}