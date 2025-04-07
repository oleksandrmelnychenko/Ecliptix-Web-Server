using System.Runtime.CompilerServices;

namespace Ecliptix.Core.Protocol.Utilities;

public class ShieldFailure
{
    public string Message { get; }
    public ShieldFailure(string message) => Message = string.IsNullOrWhiteSpace(message) ? "Unknown error" : message;

    [MethodImpl(MethodImplOptions.AggressiveInlining)] public static ShieldFailure DeriveKeyFailed(string details) => new($"Key derivation failed: {details}");
    [MethodImpl(MethodImplOptions.AggressiveInlining)] public static ShieldFailure KeyRotationFailed(string details) => new($"Key rotation failed: {details}");
    [MethodImpl(MethodImplOptions.AggressiveInlining)] public static ShieldFailure InvalidInput(string details) => new($"Invalid input: {details}");
    [MethodImpl(MethodImplOptions.AggressiveInlining)] public static ShieldFailure Disposed() => new("Object disposed");
    public static ShieldFailure PeerPubKeyFailed(string details) => new($"PeerPubKeyFailed: {details}");
    public static ShieldFailure HandshakeFailed(string details) => new($"HandshakeFailed: {details}");
    public override string ToString() => Message;
}