namespace Ecliptix.Core.Infrastructure.Grpc.Constants;

public static class InterceptorConstants
{
    public static class Telemetry
    {
        public const string GrpcTelemetryMeter = "Ecliptix.GrpcTelemetry";
    }

    public static class StatusMessages
    {
        public const string Ok = "OK";
        public const string Internal = "INTERNAL";
    }

    public static class Connections
    {
        public const string UniqueConnectIdKey = "UniqueConnectId";
    }

    public static class Metrics
    {
        public const string GrpcRequestsTotal = "grpc_requests_total";
        public const string GrpcRequestsTotalDescription = "Total number of gRPC requests";
    }

    public static class LogMessages
    {
        public const string GrpcUnhandledException = "An unhandled exception was thrown during gRPC call {Method}.";
    }

    public static class Characters
    {
        public const char Space = ' ';
    }

    public static class Numbers
    {
        public const int One = 1;
    }
}
