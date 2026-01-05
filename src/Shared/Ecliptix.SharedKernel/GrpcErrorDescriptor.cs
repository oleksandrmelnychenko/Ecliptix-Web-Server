using Grpc.Core;

namespace Ecliptix.SharedKernel;

public sealed record GrpcErrorDescriptor(
    ErrorCode ErrorCode,
    StatusCode StatusCode,
    string I18nKey,
    bool Retryable = false,
    int? RetryAfterMilliseconds = null)
{
    public Status CreateStatus(string message) => new(StatusCode, message);
}
