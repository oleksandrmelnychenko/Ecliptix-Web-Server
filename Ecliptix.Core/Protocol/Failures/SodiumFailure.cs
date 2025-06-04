using Grpc.Core;

namespace Ecliptix.Core.Protocol.Failures;

public class SodiumFailure
{
    public SodiumFailureType Type { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    private SodiumFailure(SodiumFailureType type, string message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }

    public static SodiumFailure InitializationFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.InitializationFailed, details, inner);

    public static SodiumFailure LibraryNotFound(string details, Exception? inner = null) =>
        new(SodiumFailureType.LibraryNotFound, details, inner);

    public static SodiumFailure AllocationFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.AllocationFailed, details, inner);

    public static SodiumFailure MemoryPinningFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.MemoryPinningFailed, details, inner);

    public static SodiumFailure SecureWipeFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.SecureWipeFailed, details, inner);

    public static SodiumFailure MemoryProtectionFailed(string details, Exception? inner = null) =>
        new(SodiumFailureType.MemoryProtectionFailed, details, inner);

    public static SodiumFailure NullPointer(string details) =>
        new(SodiumFailureType.NullPointer, details);

    public static SodiumFailure InvalidBufferSize(string details) =>
        new(SodiumFailureType.InvalidBufferSize, details);

    public static SodiumFailure BufferTooSmall(string details) =>
        new(SodiumFailureType.BufferTooSmall, details);

    public static SodiumFailure BufferTooLarge(string details) =>
        new(SodiumFailureType.BufferTooLarge, details);

    public override string ToString() =>
        $"SodiumFailure(Type={Type}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";

    public override bool Equals(object? obj) =>
        obj is SodiumFailure other &&
        Type == other.Type &&
        Message == other.Message &&
        Equals(InnerException, other.InnerException);

    public override int GetHashCode() =>
        HashCode.Combine(Type, Message, InnerException);
}