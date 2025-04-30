using System.Runtime.CompilerServices;
using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public class ShieldFailure
{
    public ShieldFailureType Type { get; }
    public string Message { get; }
    public Exception? InnerException { get; }

    private ShieldFailure(ShieldFailureType type, string message, Exception? innerException = null)
    {
        Type = type;
        Message = message;
        InnerException = innerException;
    }

    public static Status ToGrpcStatus(ShieldFailure failure)
    {
        StatusCode code = failure.Type switch
        {
            ShieldFailureType.InvalidInput => StatusCode.InvalidArgument,
            ShieldFailureType.ObjectDisposed => StatusCode.FailedPrecondition,
            ShieldFailureType.EphemeralMissing => StatusCode.FailedPrecondition,
            ShieldFailureType.StateMissing => StatusCode.FailedPrecondition,
            _ => StatusCode.Internal
        };

        string message = code == StatusCode.Internal ? "An internal error occurred." : failure.Message;

        return new Status(code, message);
    }

    private static string GetDefaultMessage(ShieldFailureType type) => type switch
    {
        ShieldFailureType.Generic => "An unspecified error occurred.",
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
        ShieldFailureType.InvalidInput => "Invalid input provided.",
        ShieldFailureType.ObjectDisposed => "Cannot access a disposed object.",
        ShieldFailureType.AllocationFailed => "Memory allocation failed.",
        ShieldFailureType.PinningFailure => "Failed to pin memory.",
        ShieldFailureType.BufferTooSmall => "Provided buffer is too small.",
        ShieldFailureType.DataTooLarge => "Provided data exceeds buffer capacity.",
        ShieldFailureType.DataAccessError => "Error accessing data.",
        _ => $"Unknown Shield protocol error: {type}"
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Generic(string? details = null, Exception? inner = null) =>
        new(ShieldFailureType.Generic, details ?? GetDefaultMessage(ShieldFailureType.Generic), inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Decode(string details, Exception? inner = null) =>
        new(ShieldFailureType.DecodeFailed, details, inner);
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure ActorRefNotFound(string details, Exception? inner = null) =>
        new(ShieldFailureType.DecodeFailed, details, inner);
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure ActorNotCreated(string details, Exception? inner = null) =>
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
    public static ShieldFailure InvalidInput(string details) =>
        new(ShieldFailureType.InvalidInput, details);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure ObjectDisposed(string resourceName) =>
        new(ShieldFailureType.ObjectDisposed, $"Cannot access disposed resource '{resourceName}'.");

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure AllocationFailed(string details, Exception? inner = null) =>
        new(ShieldFailureType.AllocationFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure PinningFailure(string details, Exception? inner = null) =>
        new(ShieldFailureType.PinningFailure, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure BufferTooSmall(string details) =>
        new(ShieldFailureType.BufferTooSmall, details);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure DataTooLarge(string details) =>
        new(ShieldFailureType.DataTooLarge, details);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure DataAccess(string details, Exception? inner = null) =>
        new(ShieldFailureType.DataAccessError, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure KeyGeneration(string details, Exception? inner = null) =>
        new(ShieldFailureType.KeyGenerationFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure PrepareLocal(string details, Exception? inner = null) =>
        new(ShieldFailureType.KeyGenerationFailed, details, inner);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure SessionExpired(string details, Exception? inner = null) =>
        new(ShieldFailureType.SessionExpired, details, inner);

    public override string ToString() =>
        $"ShieldFailure(Type={Type}, Message='{Message}'{(InnerException != null ? $", InnerException='{InnerException.GetType().Name}: {InnerException.Message}'" : "")})";

    public override bool Equals(object? obj) =>
        obj is ShieldFailure other &&
        Type == other.Type &&
        Message == other.Message &&
        Equals(InnerException, other.InnerException);

    public override int GetHashCode() =>
        HashCode.Combine(Type, Message, InnerException);
}