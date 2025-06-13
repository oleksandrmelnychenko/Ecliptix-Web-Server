namespace Ecliptix.Core.Protocol.Failures;

public class SodiumFailure
{
    private SodiumFailure(SodiumFailureType type, string message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }

    public SodiumFailureType Type { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    public static SodiumFailure InitializationFailed(string details, Exception? inner = null)
    {
        return new SodiumFailure(SodiumFailureType.InitializationFailed, details, inner);
    }

    public static SodiumFailure LibraryNotFound(string details, Exception? inner = null)
    {
        return new SodiumFailure(SodiumFailureType.LibraryNotFound, details, inner);
    }

    public static SodiumFailure AllocationFailed(string details, Exception? inner = null)
    {
        return new SodiumFailure(SodiumFailureType.AllocationFailed, details, inner);
    }

    public static SodiumFailure MemoryPinningFailed(string details, Exception? inner = null)
    {
        return new SodiumFailure(SodiumFailureType.MemoryPinningFailed, details, inner);
    }

    public static SodiumFailure SecureWipeFailed(string details, Exception? inner = null)
    {
        return new SodiumFailure(SodiumFailureType.SecureWipeFailed, details, inner);
    }

    public static SodiumFailure MemoryProtectionFailed(string details, Exception? inner = null)
    {
        return new SodiumFailure(SodiumFailureType.MemoryProtectionFailed, details, inner);
    }

    public static SodiumFailure NullPointer(string details)
    {
        return new SodiumFailure(SodiumFailureType.NullPointer, details);
    }

    public static SodiumFailure InvalidBufferSize(string details)
    {
        return new SodiumFailure(SodiumFailureType.InvalidBufferSize, details);
    }

    public static SodiumFailure BufferTooSmall(string details)
    {
        return new SodiumFailure(SodiumFailureType.BufferTooSmall, details);
    }

    public static SodiumFailure BufferTooLarge(string details)
    {
        return new SodiumFailure(SodiumFailureType.BufferTooLarge, details);
    }

    public override string ToString()
    {
        return
            $"SodiumFailure(Type={Type}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";
    }

    public override bool Equals(object? obj)
    {
        return obj is SodiumFailure other &&
               Type == other.Type &&
               Message == other.Message &&
               Equals(InnerException, other.InnerException);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Message, InnerException);
    }
}