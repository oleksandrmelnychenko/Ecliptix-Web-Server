using System.Runtime.CompilerServices;

namespace Ecliptix.Core.Protocol.Utilities;

/// <summary>
/// Represents an error within the Shield protocol layer.
/// </summary>
public sealed class ShieldFailure : Exception
{
    public ShieldFailureType Type { get; }
    public override string Message { get; }
    public Exception? InnerException { get; }

    private ShieldFailure(ShieldFailureType type, string message, Exception? innerException = null)
    {
        Type = type;
        Message = string.IsNullOrWhiteSpace(message) ? GetDefaultMessage(type) : message;
        InnerException = innerException;
    }

    private static string GetDefaultMessage(ShieldFailureType type) => type switch
    {
        ShieldFailureType.Generic => "An unspecified error occurred in the Shield protocol.",
        ShieldFailureType.DecodeFailed => "Failed to decode or deserialize data.",
        ShieldFailureType.EphemeralMissing => "Ephemeral secret missing during operation.",
        ShieldFailureType.ConversionFailed => "Failed to convert data between types.",
        ShieldFailureType.PrepareLocalFailed => "Failed to set up local state for exchange.",
        ShieldFailureType.StateMissing => "Required session state or key material not found.",
        ShieldFailureType.DeriveKeyFailed => "Failed to derive cryptographic key.",
        ShieldFailureType.PeerPubKeyFailed => "Failed to process peer's public key.",
        ShieldFailureType.PeerExchangeFailed => "Failed to decode peer's exchange payload.",
        ShieldFailureType.KeyRotationFailed => "Failed to rotate or replenish keys.",
        ShieldFailureType.HandshakeFailed => "Failed to complete key exchange handshake.",
        ShieldFailureType.DecryptFailed => "Failed to decrypt data.",
        ShieldFailureType.StoreOpFailed => "Failed to interact with persistent storage.",
        ShieldFailureType.InvalidKeySize => "Key data has an invalid size.",
        ShieldFailureType.InvalidEd25519Key => "Ed25519 key data is invalid.",
        ShieldFailureType.SpkVerificationFailed => "SPK signature verification failed.",
        ShieldFailureType.HkdfInfoEmpty => "HKDF info parameter cannot be empty.",
        ShieldFailureType.KeyGenerationFailed => "Failed to generate cryptographic key.",
        ShieldFailureType.EncryptionFailed => "Failed to encrypt data.",
        _ => $"Unknown Shield protocol error: {type}"
    };

    // Factory methods for common errors
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Generic(string? details = null, Exception? inner = null) =>
        new(ShieldFailureType.Generic, details ?? GetDefaultMessage(ShieldFailureType.Generic), inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Decode(string details, Exception? inner = null) =>
        new(ShieldFailureType.DecodeFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure DeriveKey(string details, Exception? inner = null) =>
        new(ShieldFailureType.DeriveKeyFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure KeyRotation(string details, Exception? inner = null) =>
        new(ShieldFailureType.KeyRotationFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Handshake(string details, Exception? inner = null) =>
        new(ShieldFailureType.HandshakeFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure PeerPubKey(string details, Exception? inner = null) =>
        new(ShieldFailureType.PeerPubKeyFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure InvalidInput(string details, Exception? inner = null) =>
        new(ShieldFailureType.Generic, $"Invalid input: {details}", inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Disposed(Exception? inner = null) =>
        new(ShieldFailureType.Generic, "Object disposed", inner);

    public override string ToString() =>
        $"ShieldFailure(Type={Type}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";

    // For equality comparison in Result<T, ShieldFailure>
    public override bool Equals(object? obj) =>
        obj is ShieldFailure other &&
        Type == other.Type &&
        Message == other.Message &&
        ReferenceEquals(InnerException, other.InnerException);

    public override int GetHashCode() =>
        HashCode.Combine(Type, Message, InnerException);
}