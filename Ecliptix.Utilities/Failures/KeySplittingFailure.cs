using Grpc.Core;

namespace Ecliptix.Utilities.Failures;

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

    public override Status ToGrpcStatus()
    {
        StatusCode code = Type switch
        {
            KeySplittingFailureType.InvalidThreshold => StatusCode.InvalidArgument,
            KeySplittingFailureType.InvalidShareCount => StatusCode.InvalidArgument,
            KeySplittingFailureType.InvalidKeyLength => StatusCode.InvalidArgument,
            KeySplittingFailureType.InvalidKeyData => StatusCode.InvalidArgument,
            KeySplittingFailureType.InvalidShareData => StatusCode.InvalidArgument,
            KeySplittingFailureType.InvalidIdentifier => StatusCode.InvalidArgument,
            KeySplittingFailureType.InsufficientShares => StatusCode.FailedPrecondition,
            _ => StatusCode.Internal
        };

        return new Status(code, Message);
    }

    public override object ToStructuredLog()
    {
        return new
        {
            KeySplittingFailureType = Type.ToString(),
            Message,
            InnerException,
            Timestamp
        };
    }
}
