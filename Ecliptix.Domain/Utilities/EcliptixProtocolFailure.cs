using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public class EcliptixProtocolFailure
{
    private EcliptixProtocolFailure(EcliptixProtocolFailureType failureType, string message,
        Exception? innerException = null)
    {
        FailureType = failureType;
        Message = message;
        InnerException = innerException;
    }

    public EcliptixProtocolFailureType FailureType { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    public static Status ToGrpcStatus(EcliptixProtocolFailure failure)
    {
        StatusCode code = failure.FailureType switch
        {
            EcliptixProtocolFailureType.InvalidInput => StatusCode.InvalidArgument,
            EcliptixProtocolFailureType.ObjectDisposed => StatusCode.FailedPrecondition,
            EcliptixProtocolFailureType.EphemeralMissing => StatusCode.FailedPrecondition,
            EcliptixProtocolFailureType.StateMissing => StatusCode.FailedPrecondition,
            _ => StatusCode.Internal
        };

        string message = code == StatusCode.Internal && failure.FailureType != EcliptixProtocolFailureType.Generic
            ? "An internal error occurred."
            : failure.Message;

        return new Status(code, message);
    }

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
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DecodeFailed, details, inner);
    }

    public static EcliptixProtocolFailure ActorNotCreated(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DecodeFailed, details, inner);
    }

    public static EcliptixProtocolFailure DeriveKey(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.DeriveKeyFailed, details, inner);
    }

    public static EcliptixProtocolFailure KeyRotation(string details, Exception? inner = null)
    {
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.KeyRotationFailed, details, inner);
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
        return new EcliptixProtocolFailure(EcliptixProtocolFailureType.ObjectDisposed,
            $"Cannot access disposed resource '{resourceName}'.");
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

    public override string ToString()
    {
        return
            $"EcliptixProtocolFailure(Type={FailureType}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";
    }

    public override bool Equals(object? obj)
    {
        return obj is EcliptixProtocolFailure other &&
               FailureType == other.FailureType &&
               Message == other.Message &&
               Equals(InnerException, other.InnerException);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(FailureType, Message, InnerException);
    }
}