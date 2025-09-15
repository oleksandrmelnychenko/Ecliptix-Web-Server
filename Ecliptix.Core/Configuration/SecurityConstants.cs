namespace Ecliptix.Core.Configuration;

public static class SecurityConstants
{
    public static class EnvironmentVariables
    {
        public const string ApplicationInsightsConnectionString = "APPLICATIONINSIGHTS_CONNECTION_STRING";
    }

    public static class HttpHeaders
    {
        public const string XFrameOptions = "X-Frame-Options";
        public const string XForwardedFor = "X-Forwarded-For";
        public const string XRealIP = "X-Real-IP";
        public const string UserAgent = "User-Agent";
        public const string RetryAfter = "Retry-After";
        public const string XConnectId = "X-Connect-Id";
    }

    public static class SecurityValues
    {
        public const string DenyFrameOptions = "DENY";
        public const string UnknownIpAddress = "unknown";
        public const string SanitizedValue = "sanitized";
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

    public static class StatusCodes
    {
        public const int BadRequestThreshold = 400;
    }

    public static class Limits
    {
        public const int MaxHeaderLengthBytes = 8192;
        public const int MinSecretKeySeedLengthBytes = 32;
    }

    public static class StatusMessages
    {
        public const string ServerUpAndRunning = "Server is up and running";
        public const string Success = "Success";
        public const string UnsupportedContentType = "Unsupported content type";
        public const string InvalidHeaders = "Invalid headers";
        public const string ResourceExhaustionDetected = "Resource exhaustion detected from {IpAddress}: {Message}";
        public const string UnhandledException = "Unhandled exception in security middleware from {IpAddress}";
        public const string SuspiciousHeaderLength = "Suspicious header detected - excessive length: {HeaderName}";
        public const string SuspiciousHeaderName = "Suspicious header name detected: {HeaderName}";
        public const string SecurityMiddlewareProcessing = "Security middleware processing request: {@RequestInfo}";
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