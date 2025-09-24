namespace Ecliptix.Domain.Memberships.OPAQUE;

/// <summary>
/// Message keys for OPAQUE error messages
/// </summary>
public static class OpaqueMessageKeys
{
    public const string TokenExpired = "Token has expired";
    public const string DecryptFailed = "Decryption failed";
    public const string EncryptFailed = "Encryption failed";
    public const string InputKeyingMaterialCannotBeNullOrEmpty = "Input keying material cannot be null or empty";
}