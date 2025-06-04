using System.Runtime.CompilerServices;
using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public class EcliptixProtocolFailure
{
    public EcliptixProtocolFailureType FailureType { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    private EcliptixProtocolFailure(EcliptixProtocolFailureType failureType, string message, Exception? innerException = null)
    {
        FailureType = failureType;
        Message = message;
        InnerException = innerException;
    }

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

    public static EcliptixProtocolFailure Generic(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.Generic, details, inner);

    public static EcliptixProtocolFailure Decode(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.DecodeFailed, details, inner);

    public static EcliptixProtocolFailure ActorRefNotFound(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.DecodeFailed, details, inner);

    public static EcliptixProtocolFailure ActorNotCreated(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.DecodeFailed, details, inner);

    public static EcliptixProtocolFailure DeriveKey(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.DeriveKeyFailed, details, inner);

    public static EcliptixProtocolFailure KeyRotation(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.KeyRotationFailed, details, inner);

    public static EcliptixProtocolFailure Handshake(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.HandshakeFailed, details, inner);

    public static EcliptixProtocolFailure PeerPubKey(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.PeerPubKeyFailed, details, inner);

    public static EcliptixProtocolFailure InvalidInput(string details) =>
        new(EcliptixProtocolFailureType.InvalidInput, details);

    public static EcliptixProtocolFailure ObjectDisposed(string resourceName) =>
        new(EcliptixProtocolFailureType.ObjectDisposed, $"Cannot access disposed resource '{resourceName}'.");

    public static EcliptixProtocolFailure AllocationFailed(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.AllocationFailed, details, inner);

    public static EcliptixProtocolFailure PinningFailure(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.PinningFailure, details, inner);

    public static EcliptixProtocolFailure BufferTooSmall(string details) =>
        new(EcliptixProtocolFailureType.BufferTooSmall, details);

    public static EcliptixProtocolFailure DataTooLarge(string details) =>
        new(EcliptixProtocolFailureType.DataTooLarge, details);

    public static EcliptixProtocolFailure KeyGeneration(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.KeyGenerationFailed, details, inner);

    public static EcliptixProtocolFailure PrepareLocal(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.PrepareLocalFailed, details, inner);

    public static EcliptixProtocolFailure MemoryBufferError(string details, Exception? inner = null) =>
        new(EcliptixProtocolFailureType.MemoryBufferError, details, inner);

    public override string ToString() =>
        $"EcliptixProtocolFailure(Type={FailureType}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";

    public override bool Equals(object? obj) =>
        obj is EcliptixProtocolFailure other &&
        FailureType == other.FailureType &&
        Message == other.Message &&
        Equals(InnerException, other.InnerException);

    public override int GetHashCode() =>
        HashCode.Combine(FailureType, Message, InnerException);
}