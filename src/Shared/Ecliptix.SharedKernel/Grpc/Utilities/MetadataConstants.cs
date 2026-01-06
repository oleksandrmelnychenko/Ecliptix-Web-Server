namespace Ecliptix.SharedKernel.Grpc.Utilities;

public static class MetadataConstants
{
    public static class Keys
    {
        public const string RequestId = "request-id";
        public const string LocalIpAddress = "local-ip-address";
        public const string PublicIpAddress = "public-ip-address";
        public const string Platform = "platform";
        public const string Locale = "lang";
        public const string CorrelationId = "correlation-id";
        public const string Version = "version";
        public const string Tenant = "tenant";
        public const string LinkId = "fetch-link";
        public const string ApplicationInstanceId = "application-identifier";
        public const string AppDeviceId = "d-identifier";
        public const string ConnectionContextId = "c-context-id";
        public const string OperationContextId = "o-context-id";
        public const string IdempotencyKey = "x-idempotency-key";
        public const string ConnectId = "connect-id";
    }

    public static class SecurityKeys
    {
        public static string KeyExchangeContextTypeKey { get; set; } = "oiwfT6c5kOQsZozxhTBg";
        public static string KeyExchangeContextTypeValue { get; set; } = "JmTGdGilMka07zyg5hz6Q";
    }

    public static class ErrorMessages
    {
        public const string InvalidGuidFormat = "Invalid Guid format for key '{0}'";
        public const string InvalidPubKeyExchangeType = "Invalid PubKeyExchangeType for key '{0}'";
        public const string InvalidConnectionIdFormat = "Invalid connect_id format";
    }

    public static class ByteLengths
    {
        public const int GuidByteLength = 16;
        public const int HashSpanLength = 4;
        public const int InitialOffset = 0;
    }
}
