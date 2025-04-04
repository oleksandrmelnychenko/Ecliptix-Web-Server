using System.Runtime.CompilerServices;

namespace Ecliptix.Core.Protocol;

public class ShieldFailure // Ensure this is not null when created
{
    public string Message { get; }
    public ShieldFailure(string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message); // Ensure message is not null/empty
        Message = message;
    }

    // Consider making these return specific derived types if more detail is needed
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure DeriveKeyFailed(string details) =>
        new($"Key derivation failed: {details}");

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure KeyRotationFailed(string details) =>
        new($"Key rotation failed: {details}");

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure InvalidInput(string details) =>
        new($"Invalid input: {details}");

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ShieldFailure Disposed() =>
        new("Object disposed");

    public override string ToString() => Message; // Simple string representation
}