using System.Runtime.CompilerServices;

namespace Ecliptix.Domain.Utilities;

public class MetaDataSystemFailure
{
    private MetaDataSystemFailure(MetaDataSystemFailureType type, string? message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }

    public MetaDataSystemFailureType Type { get; }
    public string? Message { get; }
    public Exception? InnerException { get; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static MetaDataSystemFailure ComponentNotFound(string? details = null)
    {
        return new MetaDataSystemFailure(MetaDataSystemFailureType.RequiredComponentNotFound, details);
    }
}