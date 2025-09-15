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
        public const string Error = "error";
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
        public const string InternalServerError = "Internal server error";
        public const string InternalServerErrorOccurred = "Internal server error occurred";
        public const string FailedToParseDecryptedRequest = "Failed to parse decrypted request";
        public const string ConnectionIdOutOfRange = "Connection ID out of valid range";
    }

    public static class ChannelOptions
    {
        public const int BoundedChannelCapacity = 100;
    }

    public static class ActorPaths
    {
        public const string FlowActorNameFormat = "flow-{0}";
        public const string VerificationFlowActorPathFormat = "/user/{0}/{1}";
    }

    public static class LogMessages
    {
        public const string StartingEncryptedOperation = "Starting encrypted operation {ServiceName}.{MethodName} for ConnectId {ConnectId}";
        public const string CompletedEncryptedOperation = "Completed encrypted operation {ServiceName}.{MethodName} in {Duration}ms";
        public const string UnexpectedErrorInOperation = "Unexpected error in encrypted operation {ServiceName}.{MethodName}";
        public const string UnexpectedErrorInStreamingOperation = "Unexpected error in encrypted streaming operation {ServiceName}.{MethodName}";
        public const string FailedToParseDecryptedRequestLog = "Failed to parse decrypted request for ConnectId {ConnectId}";
        public const string FailedToEncryptResponse = "Failed to encrypt response for ConnectId {ConnectId}: {Error}";
    }
}