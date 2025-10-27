namespace Ecliptix.Core.Configuration;

public static class SecurityConstants
{
    public static class EnvironmentVariables
    {
        public const string ApplicationInsightsConnectionString = "APPLICATIONINSIGHTS_CONNECTION_STRING";
    }

    public static class HttpHeaders
    {
        public const string UserAgent = "User-Agent";
        public const string XConnectId = "X-Connect-Id";
    }

    public static class SecurityValues
    {
        public const string DenyFrameOptions = "DENY";
        public const string XssProtectionValue = "1; mode=block";
        public const string NoSniff = "nosniff";
        public const string StrictOriginWhenCrossOrigin = "strict-origin-when-cross-origin";
        public const string NoIndexNoFollow = "noindex, nofollow";
        public const string ServerHeaderName = "Server";
    }

    public static class ContentTypes
    {
        public const string ApplicationGrpc = "application/grpc";
        public const string ApplicationGrpcProto = "application/grpc+proto";
        public const string ApplicationJson = "application/json";
    }

    public static class Limits
    {
        public const int MaxHeaderLengthBytes = 8192;
    }

    public static class StatusMessages
    {
        public const string UnsupportedContentType = "Unsupported content type";
        public const string InvalidHeaders = "Invalid headers";
    }

    public static class Paths
    {
        public const string Grpc = "/grpc";
    }

    public static class SuspiciousContent
    {
        public const string Script = "script";
        public const string LessThan = "<";
        public const string GreaterThan = ">";
        public const string Javascript = "javascript";
        public const string VbScript = "vbscript";
        public const string OnLoad = "onload";
        public const string OnError = "onerror";
    }
}
