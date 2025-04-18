using System.Runtime.CompilerServices;

namespace Ecliptix.Core.Protocol.Utilities;

public class MetaDataSystemFailure
{
    public MetaDataSystemFailureType Type { get; }
    public string? Message { get; }
    public Exception? InnerException { get; }

    private MetaDataSystemFailure(MetaDataSystemFailureType type, string? message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static MetaDataSystemFailure ComponentNotFound(string? details = null) =>
        new(MetaDataSystemFailureType.RequiredComponentNotFound, details);
}