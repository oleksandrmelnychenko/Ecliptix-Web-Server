using Grpc.Core;

namespace Ecliptix.Utilities;

public sealed record EcliptixProtocolFailure(
    EcliptixProtocolFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        FailureType switch
        {
            EcliptixProtocolFailureType.InvalidInput or
            EcliptixProtocolFailureType.PeerPubKeyFailed or
            EcliptixProtocolFailureType.BufferTooSmall or
            EcliptixProtocolFailureType.DataTooLarge => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                ErrorI18nKeys.Validation),

            EcliptixProtocolFailureType.ObjectDisposed or
            EcliptixProtocolFailureType.EphemeralMissing or
            EcliptixProtocolFailureType.StateMissing or
            EcliptixProtocolFailureType.ActorRefNotFound => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                ErrorI18nKeys.PreconditionFailed),

            EcliptixProtocolFailureType.ActorNotCreated => new GrpcErrorDescriptor(
                ErrorCode.DependencyUnavailable,
                StatusCode.Unavailable,
                ErrorI18nKeys.DependencyUnavailable,
                Retryable: true),

            EcliptixProtocolFailureType.HandshakeFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                ErrorI18nKeys.ServiceUnavailable,
                Retryable: true),

            EcliptixProtocolFailureType.PinningFailure => new GrpcErrorDescriptor(
                ErrorCode.DependencyUnavailable,
                StatusCode.Unavailable,
                ErrorI18nKeys.DependencyUnavailable,
                Retryable: true),

            EcliptixProtocolFailureType.AllocationFailed => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                ErrorI18nKeys.ResourceExhausted,
                Retryable: true),

            EcliptixProtocolFailureType.DeriveKeyFailed or
            EcliptixProtocolFailureType.DecodeFailed or
            EcliptixProtocolFailureType.KeyGenerationFailed or
            EcliptixProtocolFailureType.PrepareLocalFailed or
            EcliptixProtocolFailureType.MemoryBufferError => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18nKeys.Internal),

            EcliptixProtocolFailureType.Generic => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18nKeys.Internal),

            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18nKeys.Internal)
        };

    public static EcliptixProtocolFailure Generic(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, details, inner);
    }

    public static EcliptixProtocolFailure Decode(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DecodeFailed, details, inner);
    }

    public static EcliptixProtocolFailure ActorRefNotFound(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.ActorRefNotFound, details, inner);
    }

    public static EcliptixProtocolFailure ActorStateNotFound(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMissing, details, inner);
    }

    public static EcliptixProtocolFailure ActorNotCreated(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.ActorNotCreated, details, inner);
    }

    public static EcliptixProtocolFailure DeriveKey(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DeriveKeyFailed, details, inner);
    }

    public static EcliptixProtocolFailure Handshake(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.HandshakeFailed, details, inner);
    }

    public static EcliptixProtocolFailure PeerPubKey(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.PeerPubKeyFailed, details, inner);
    }

    public static EcliptixProtocolFailure InvalidInput(string details)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.InvalidInput, details);
    }

    public static EcliptixProtocolFailure ObjectDisposed(string resourceName)
    {
        return new EcliptixProtocolFailure(
            EcliptixProtocolFailureType.ObjectDisposed, $"Cannot access disposed resource '{resourceName}'.");
    }

    public static EcliptixProtocolFailure AllocationFailed(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.AllocationFailed, details, inner);
    }

    public static EcliptixProtocolFailure PinningFailure(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.PinningFailure, details, inner);
    }

    public static EcliptixProtocolFailure BufferTooSmall(string details)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.BufferTooSmall, details);
    }

    public static EcliptixProtocolFailure DataTooLarge(string details)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DataTooLarge, details);
    }

    public static EcliptixProtocolFailure KeyGeneration(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.KeyGenerationFailed, details, inner);
    }

    public static EcliptixProtocolFailure PrepareLocal(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.PrepareLocalFailed, details, inner);
    }

    public static EcliptixProtocolFailure MemoryBufferError(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.MemoryBufferError, details, inner);
    }

    public static EcliptixProtocolFailure ReplayAttempt(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, $"Replay attack detected: {details}", inner);
    }

    public override object ToStructuredLog()
    {
        return new
        {
            ProtocolFailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp
        };
    }
}
