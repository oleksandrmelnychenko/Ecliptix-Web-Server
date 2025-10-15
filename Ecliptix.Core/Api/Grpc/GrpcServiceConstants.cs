namespace Ecliptix.Core.Api.Grpc;

public static class GrpcServiceConstants
{
    public static class Activities
    {
        public const string ServiceSource = "Ecliptix.GrpcServices";
        public const string DecryptRequest = "DecryptRequest";
        public const string EncryptResponse = "EncryptResponse";
        public const string CreateFailureResponse = "CreateFailureResponse";
    }

    public static class ActivityTags
    {
        public const string GrpcService = "grpc.service";
        public const string GrpcMethod = "grpc.method";
        public const string DecryptSuccess = "decrypt_success";
        public const string HandlerSuccess = "handler_success";
        public const string DurationMs = "duration_ms";
        public const string Success = "success";
        public const string Streaming = "streaming";
        public const string ConnectId = "connect_id";
        public const string PayloadSize = "payload_size";
        public const string DecryptedSize = "decrypted_size";
        public const string ResponseSize = "response_size";
        public const string EncryptSuccess = "encrypt_success";
        public const string EncryptedSize = "encrypted_size";
        public const string FailureType = "failure_type";
    }

    public static class ErrorMessages
    {
        public const string FailedToParseDecryptedRequest = "Failed to parse decrypted request";
        public const string ConnectionIdOutOfRange = "Connection ID out of valid range";
    }

    public static class ChannelOptions
    {
        public const int BoundedChannelCapacity = 32;
    }

    public static class ActorPaths
    {
        public const string FlowActorNameFormat = "flow-{0}";
        public const string VerificationFlowActorPathFormat = "/user/{0}/{1}";
    }
}
