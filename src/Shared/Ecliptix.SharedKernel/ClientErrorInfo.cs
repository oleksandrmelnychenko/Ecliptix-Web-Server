namespace Ecliptix.SharedKernel;

public sealed record ClientErrorInfo(
    ErrorCode ErrorCode,
    string MessageKey,
    bool Retryable,
    ErrorSurface Surface,
    string PublicErrorCode,
    string? MessageFallback = null);
