using Grpc.Core;

namespace Ecliptix.SharedKernel;

public sealed record EcliptixProtocolFailure(
    EcliptixProtocolFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public override bool IsUserFacing => false;

    public override bool Retryable => FailureType switch
    {
        EcliptixProtocolFailureType.HandshakeFailed or
        EcliptixProtocolFailureType.ActorNotCreated or
        EcliptixProtocolFailureType.PinningFailure or
        EcliptixProtocolFailureType.AllocationFailed or
        EcliptixProtocolFailureType.StateMismatch or
        EcliptixProtocolFailureType.SessionAuthenticationFailed or
        EcliptixProtocolFailureType.HeaderAuthenticationFailed => true,
        _ => false
    };

    public override ErrorSurface Surface => ErrorSurface.System;

    public override string PublicErrorCode => FailureType switch
    {
        EcliptixProtocolFailureType.InvalidInput => "protocol.invalid_input",
        EcliptixProtocolFailureType.PeerPubKeyFailed => "protocol.peer_pubkey_failed",
        EcliptixProtocolFailureType.BufferTooSmall => "protocol.buffer_too_small",
        EcliptixProtocolFailureType.DataTooLarge => "protocol.data_too_large",
        EcliptixProtocolFailureType.ObjectDisposed => "protocol.object_disposed",
        EcliptixProtocolFailureType.EphemeralMissing => "protocol.ephemeral_missing",
        EcliptixProtocolFailureType.StateMissing => "protocol.state_missing",
        EcliptixProtocolFailureType.ActorRefNotFound => "protocol.actor_ref_missing",
        EcliptixProtocolFailureType.ActorNotCreated => "protocol.actor_not_created",
        EcliptixProtocolFailureType.HandshakeFailed => "protocol.handshake_failed",
        EcliptixProtocolFailureType.PinningFailure => "protocol.pinning_failed",
        EcliptixProtocolFailureType.AllocationFailed => "protocol.allocation_failed",
        EcliptixProtocolFailureType.TimestampDrift => "protocol.timestamp_drift",
        EcliptixProtocolFailureType.ReplayAttempt => "protocol.replay_attempt",
        EcliptixProtocolFailureType.StateMismatch => "protocol.state_mismatch",
        EcliptixProtocolFailureType.HeaderAuthenticationFailed => "protocol.header_auth_failed",
        EcliptixProtocolFailureType.SessionAuthenticationFailed => "protocol.session_auth_failed",
        _ => "protocol.internal"
    };

    public override string? UserMessageKey => GetDefaultI18NKey(FailureType);

    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        FailureType switch
        {
            EcliptixProtocolFailureType.InvalidInput or
            EcliptixProtocolFailureType.PeerPubKeyFailed or
            EcliptixProtocolFailureType.BufferTooSmall or
            EcliptixProtocolFailureType.DataTooLarge => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                UserMessageKey ?? ErrorI18NKeys.Validation),

            EcliptixProtocolFailureType.ObjectDisposed or
            EcliptixProtocolFailureType.EphemeralMissing or
            EcliptixProtocolFailureType.StateMissing or
            EcliptixProtocolFailureType.ActorRefNotFound => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                UserMessageKey ?? ErrorI18NKeys.PreconditionFailed),

            EcliptixProtocolFailureType.ActorNotCreated => new GrpcErrorDescriptor(
                ErrorCode.DependencyUnavailable,
                StatusCode.Unavailable,
                UserMessageKey ?? ErrorI18NKeys.DependencyUnavailable,
                Retryable: true),

            EcliptixProtocolFailureType.HandshakeFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                UserMessageKey ?? ErrorI18NKeys.ServiceUnavailable,
                Retryable: true),

            EcliptixProtocolFailureType.PinningFailure => new GrpcErrorDescriptor(
                ErrorCode.DependencyUnavailable,
                StatusCode.Unavailable,
                UserMessageKey ?? ErrorI18NKeys.DependencyUnavailable,
                Retryable: true),

            EcliptixProtocolFailureType.AllocationFailed => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                UserMessageKey ?? ErrorI18NKeys.ResourceExhausted,
                Retryable: true),

            EcliptixProtocolFailureType.TimestampDrift => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                UserMessageKey ?? ErrorI18NKeys.Validation),

            EcliptixProtocolFailureType.ReplayAttempt => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                UserMessageKey ?? ErrorI18NKeys.PreconditionFailed),

            EcliptixProtocolFailureType.StateMismatch => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                UserMessageKey ?? ErrorI18NKeys.PreconditionFailed,
                Retryable: true),

            EcliptixProtocolFailureType.HeaderAuthenticationFailed or
            EcliptixProtocolFailureType.SessionAuthenticationFailed => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                UserMessageKey ?? ErrorI18NKeys.PreconditionFailed,
                Retryable: true),

            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                UserMessageKey ?? ErrorI18NKeys.Internal)
        };

    public static EcliptixProtocolFailure Generic(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.Generic, details, inner);
    }

    public static EcliptixProtocolFailure Decode(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DecodeFailed, details, inner);
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

    public static EcliptixProtocolFailure TimestampDrift(string details)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.TimestampDrift, details);
    }

    public static EcliptixProtocolFailure ReplayAttempt(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.ReplayAttempt, $"Replay attack detected: {details}", inner);
    }

    public static EcliptixProtocolFailure StateMismatch(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.StateMismatch, details, inner);
    }

    public static EcliptixProtocolFailure HeaderAuthFailed(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.HeaderAuthenticationFailed, details, inner);
    }

    public static EcliptixProtocolFailure SessionAuthFailed(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.SessionAuthenticationFailed, details, inner);
    }

    private static string GetDefaultI18NKey(EcliptixProtocolFailureType failureType) =>
        failureType switch
        {
            EcliptixProtocolFailureType.InvalidInput => ErrorI18NKeys.Validation,
            EcliptixProtocolFailureType.PeerPubKeyFailed => ErrorI18NKeys.Validation,
            EcliptixProtocolFailureType.BufferTooSmall => ErrorI18NKeys.Validation,
            EcliptixProtocolFailureType.DataTooLarge => ErrorI18NKeys.Validation,
            EcliptixProtocolFailureType.ObjectDisposed => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.EphemeralMissing => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.StateMissing => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.ActorRefNotFound => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.ActorNotCreated => ErrorI18NKeys.DependencyUnavailable,
            EcliptixProtocolFailureType.HandshakeFailed => ErrorI18NKeys.ServiceUnavailable,
            EcliptixProtocolFailureType.PinningFailure => ErrorI18NKeys.DependencyUnavailable,
            EcliptixProtocolFailureType.AllocationFailed => ErrorI18NKeys.ResourceExhausted,
            EcliptixProtocolFailureType.TimestampDrift => ErrorI18NKeys.Validation,
            EcliptixProtocolFailureType.ReplayAttempt => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.StateMismatch => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.HeaderAuthenticationFailed => ErrorI18NKeys.PreconditionFailed,
            EcliptixProtocolFailureType.SessionAuthenticationFailed => ErrorI18NKeys.PreconditionFailed,
            _ => ErrorI18NKeys.Internal
        };

    public override object ToStructuredLog()
    {
        return new
        {
            ProtocolFailureType = FailureType.ToString(),
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
