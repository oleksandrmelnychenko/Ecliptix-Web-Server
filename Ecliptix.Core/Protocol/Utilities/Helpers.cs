using System.Security.Cryptography;
using Google.Protobuf;

namespace Ecliptix.Core.Protocol.Utilities;

public static class Helpers
{
    // Existing Rng instance
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    // Existing method
    public static uint GenerateRandomUInt32(bool excludeZero = false)
    {
        byte[] buffer = new byte[sizeof(uint)];
        uint value;
        do
        {
            Rng.GetBytes(buffer);
            value = BitConverter.ToUInt32(buffer, 0);
        } while (excludeZero && value == 0);
        return value;
    }

    /// <summary>
    /// Generates a cryptographically secure random byte array (tag) of the specified length.
    /// Useful for generating unique identifiers, salts, or other random tokens.
    /// NOTE: This is NOT typically used to generate the authentication tag for AEAD schemes;
    /// that tag is an output of the encryption process itself.
    /// </summary>
    /// <param name="tagLengthBytes">The desired length of the tag in bytes.</param>
    /// <returns>A new byte array containing cryptographically secure random bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if tagLengthBytes is less than 1.</exception>
    public static byte[] GenerateSecureRandomTag(int tagLengthBytes)
    {
        if (tagLengthBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(tagLengthBytes), "Tag length must be at least 1 byte.");
        }

        byte[] tagBytes = new byte[tagLengthBytes];
        Rng.GetBytes(tagBytes); // Fill the array with secure random bytes
        return tagBytes;
    }

    // --- Optional: Span-based version (more efficient if caller has buffer) ---

    /// <summary>
    /// Fills the provided buffer with cryptographically secure random bytes.
    /// Useful for generating unique identifiers, salts, or other random tokens directly into a buffer.
    /// NOTE: This is NOT typically used to generate the authentication tag for AEAD schemes.
    /// </summary>
    /// <param name="destination">The span buffer to fill with random bytes.</param>
    /// <exception cref="ArgumentException">Thrown if the destination span is empty.</exception>
    internal static void GenerateSecureRandomTag(Span<byte> destination)
    {
        if (destination.IsEmpty)
        {
            throw new ArgumentException("Destination buffer cannot be empty.", nameof(destination));
        }
        Rng.GetBytes(destination); // Fill the provided span
    }
    
    public static T ParseFromBytes<T>(byte[] data) where T : IMessage<T>, new() {
        MessageParser<T> parser = new(() => new T());
        return parser.ParseFrom(data);
    }

}