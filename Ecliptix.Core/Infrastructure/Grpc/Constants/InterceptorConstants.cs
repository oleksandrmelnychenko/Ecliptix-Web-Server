namespace Ecliptix.Core.Infrastructure.Grpc.Constants;

public static class InterceptorConstants
{
    public static class Telemetry
    {
        public const string GrpcInterceptorsActivitySource = "Ecliptix.GrpcInterceptors";
        public const string GrpcTelemetryMeter = "Ecliptix.GrpcTelemetry";
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

    public static class StatusMessages
    {
        public const string Ok = "OK";
        public const string Internal = "INTERNAL";
        public const string UnexpectedInternalServerError = "An unexpected internal server error occurred.";
    }

    public static class Connections
    {
        public const string UniqueConnectIdKey = "UniqueConnectId";
        public const string Unknown = "unknown";
        public const string Sanitized = "sanitized";
    }

    public static class Metrics
    {
        public const string GrpcRequestsTotal = "grpc_requests_total";
        public const string GrpcRequestsTotalDescription = "Total number of gRPC requests";
    }

    public static class Limits
    {
        public const int MaxUserAgentLength = 200;
        public const uint MaxConnectId = uint.MaxValue - 1000;
    }

    public static class LogMessages
    {
        public const string GrpcCallUnexpectedError = "Unexpected error in gRPC call {Method} after {Duration}ms";
        public const string GrpcStreamingError =
            "Error in gRPC streaming call {Method} after {Duration}ms from client {ClientHash}";
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