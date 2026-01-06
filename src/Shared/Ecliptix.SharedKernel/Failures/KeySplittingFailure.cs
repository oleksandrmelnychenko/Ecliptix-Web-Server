using Grpc.Core;

namespace Ecliptix.SharedKernel.Failures;

public enum KeySplittingFailureType
{
    InvalidThreshold,
    InvalidShareCount,
    InvalidKeyLength,
    InvalidKeyData,
    InvalidShareData,
    KeySplittingFailed,
    KeyReconstructionFailed,
    ShareValidationFailed,
    InsufficientShares,
    HmacKeyStorageFailed,
    HmacKeyMissing,
    HmacKeyRetrievalFailed,
    HmacKeyRemovalFailed,
    InvalidIdentifier,
    KeyDerivationFailed,
    AllocationFailed,
    MemoryReadFailed,
    MemoryWriteFailed
}

public sealed record KeySplittingFailure(KeySplittingFailureType Type, string Message, Exception? InnerException = null) : FailureBase(Message, InnerException)
{
    public override bool IsUserFacing => Type switch
    {
        KeySplittingFailureType.InvalidThreshold or
        KeySplittingFailureType.InvalidShareCount or
        KeySplittingFailureType.InvalidKeyLength or
        KeySplittingFailureType.InvalidKeyData or
        KeySplittingFailureType.InvalidShareData or
        KeySplittingFailureType.InvalidIdentifier or
        KeySplittingFailureType.ShareValidationFailed or
        KeySplittingFailureType.InsufficientShares => true,
        _ => false
    };

    public override bool Retryable => Type switch
    {
        KeySplittingFailureType.AllocationFailed => true,
        _ => false
    };

    public override ErrorSurface Surface => Type switch
    {
        KeySplittingFailureType.AllocationFailed => ErrorSurface.System,
        _ => ErrorSurface.User
    };

    public override string PublicErrorCode => Type switch
    {
        KeySplittingFailureType.InvalidThreshold => "keysplitting.invalid_threshold",
        KeySplittingFailureType.InvalidShareCount => "keysplitting.invalid_share_count",
        KeySplittingFailureType.InvalidKeyLength => "keysplitting.invalid_key_length",
        KeySplittingFailureType.InvalidKeyData => "keysplitting.invalid_key_data",
        KeySplittingFailureType.InvalidShareData => "keysplitting.invalid_share_data",
        KeySplittingFailureType.InvalidIdentifier => "keysplitting.invalid_identifier",
        KeySplittingFailureType.ShareValidationFailed => "keysplitting.share_validation_failed",
        KeySplittingFailureType.InsufficientShares => "keysplitting.insufficient_shares",
        KeySplittingFailureType.HmacKeyMissing => "keysplitting.hmac_missing",
        KeySplittingFailureType.AllocationFailed => "keysplitting.allocation_failed",
        _ => "keysplitting.internal"
    };

    public override string? UserMessageKey => GetDefaultI18NKey(Type);

    public static KeySplittingFailure InvalidThreshold(int threshold, int totalShares) =>
        new(KeySplittingFailureType.InvalidThreshold, $"Invalid threshold: {threshold} for {totalShares} shares");

    public static KeySplittingFailure InvalidShareCount(int count) =>
        new(KeySplittingFailureType.InvalidShareCount, $"Invalid share count: {count}");

    public static KeySplittingFailure InvalidKeyLength(int length) =>
        new(KeySplittingFailureType.InvalidKeyLength, $"Invalid key length: {length}");

    public static KeySplittingFailure InvalidKeyData(string details) =>
        new(KeySplittingFailureType.InvalidKeyData, details);

    public static KeySplittingFailure InvalidShareData(string details) =>
        new(KeySplittingFailureType.InvalidShareData, details);

    public static KeySplittingFailure KeySplittingFailed(string details, Exception? inner = null) =>
        new(KeySplittingFailureType.KeySplittingFailed, details, inner);

    public static KeySplittingFailure KeyReconstructionFailed(string details, Exception? inner = null) =>
        new(KeySplittingFailureType.KeyReconstructionFailed, details, inner);

    public static KeySplittingFailure ShareValidationFailed(string details) =>
        new(KeySplittingFailureType.ShareValidationFailed, details);

    public static KeySplittingFailure InsufficientShares(int provided, int required) =>
        new(KeySplittingFailureType.InsufficientShares, $"Insufficient shares: {provided} provided, {required} required");

    public static KeySplittingFailure HmacKeyStorageFailed(string details) =>
        new(KeySplittingFailureType.HmacKeyStorageFailed, details);

    public static KeySplittingFailure HmacKeyMissing(string identifier) =>
        new(KeySplittingFailureType.HmacKeyMissing, $"HMAC key missing for identifier: {identifier}");

    public static KeySplittingFailure HmacKeyRetrievalFailed(string details) =>
        new(KeySplittingFailureType.HmacKeyRetrievalFailed, details);

    public static KeySplittingFailure HmacKeyRemovalFailed(string details) =>
        new(KeySplittingFailureType.HmacKeyRemovalFailed, details);

    public static KeySplittingFailure InvalidIdentifier(string details) =>
        new(KeySplittingFailureType.InvalidIdentifier, details);

    public static KeySplittingFailure KeyDerivationFailed(string details, Exception? inner = null) =>
        new(KeySplittingFailureType.KeyDerivationFailed, details, inner);

    public static KeySplittingFailure AllocationFailed(string details) =>
        new(KeySplittingFailureType.AllocationFailed, details);

    public static KeySplittingFailure MemoryReadFailed(string details) =>
        new(KeySplittingFailureType.MemoryReadFailed, details);

    public static KeySplittingFailure MemoryWriteFailed(string details) =>
        new(KeySplittingFailureType.MemoryWriteFailed, details);

    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        Type switch
        {
            KeySplittingFailureType.InvalidThreshold or
            KeySplittingFailureType.InvalidShareCount or
            KeySplittingFailureType.InvalidKeyLength or
            KeySplittingFailureType.InvalidKeyData or
            KeySplittingFailureType.InvalidShareData or
            KeySplittingFailureType.InvalidIdentifier or
            KeySplittingFailureType.ShareValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                ErrorI18NKeys.Validation),

            KeySplittingFailureType.InsufficientShares => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                ErrorI18NKeys.PreconditionFailed),

            KeySplittingFailureType.HmacKeyMissing => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                ErrorI18NKeys.NotFound),

            KeySplittingFailureType.AllocationFailed => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                ErrorI18NKeys.ResourceExhausted,
                Retryable: true),

            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                UserMessageKey ?? ErrorI18NKeys.Internal)
        };

    private static string GetDefaultI18NKey(KeySplittingFailureType type) =>
        type switch
        {
            KeySplittingFailureType.InvalidThreshold => ErrorI18NKeys.Validation,
            KeySplittingFailureType.InvalidShareCount => ErrorI18NKeys.Validation,
            KeySplittingFailureType.InvalidKeyLength => ErrorI18NKeys.Validation,
            KeySplittingFailureType.InvalidKeyData => ErrorI18NKeys.Validation,
            KeySplittingFailureType.InvalidShareData => ErrorI18NKeys.Validation,
            KeySplittingFailureType.InvalidIdentifier => ErrorI18NKeys.Validation,
            KeySplittingFailureType.ShareValidationFailed => ErrorI18NKeys.Validation,
            KeySplittingFailureType.InsufficientShares => ErrorI18NKeys.PreconditionFailed,
            KeySplittingFailureType.HmacKeyMissing => ErrorI18NKeys.NotFound,
            KeySplittingFailureType.AllocationFailed => ErrorI18NKeys.ResourceExhausted,
            _ => ErrorI18NKeys.Internal
        };

    public override object ToStructuredLog()
    {
        return new
        {
            KeySplittingFailureType = Type.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsUserFacing,
            Retryable,
            Surface = Surface.ToString(),
            PublicErrorCode
        };
    }
}
