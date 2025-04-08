namespace Ecliptix.Core.Protocol.Utilities;

/// <summary>
/// Represents a detailed error within the Shield protocol layer.
/// </summary>
public sealed class ShieldError(ShieldFailureType type, string message, Exception? innerException = null): Exception 
{
    public ShieldFailureType Type { get; } = type;
    public string Message { get; } = string.IsNullOrWhiteSpace(message) ? GetDefaultMessage(type) : message;
    public Exception? InnerException { get; } = innerException;

    public ShieldError(ShieldFailureType type, Exception? innerException = null) : this(type, GetDefaultMessage(type), innerException) { }

    private static string GetDefaultMessage(ShieldFailureType type) => type switch
    {
        ShieldFailureType.EphemeralMissing => "Ephemeral secret missing during operation.",
        ShieldFailureType.HkdfInfoEmpty => "HKDF info parameter cannot be empty.",
        _ => $"A Shield protocol error occurred: {type}"
    };

    public override string ToString() => $"ShieldError(Type={Type}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";

    public static ShieldError Decode(string details, Exception? inner = null) => new(ShieldFailureType.DecodeFailed, details, inner);
    public static ShieldError Handshake(string details, Exception? inner = null) => new(ShieldFailureType.HandshakeFailed, details, inner);
    public static ShieldError DeriveKey(string details, Exception? inner = null) => new(ShieldFailureType.DeriveKeyFailed, details, inner);
}