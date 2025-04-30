using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Domain.Utilities;

// Required for AesGcm

// For Constants, ShieldChainStepException

namespace Ecliptix.Core.Protocol; // Or your preferred namespace

/// <summary>
/// Provides AES-256-GCM authenticated encryption and decryption services using the built-in .NET API.
/// WARNING: Nonce uniqueness per key is CRITICAL for AES-GCM security.
/// </summary>
public static class AesGcmService
{
    private const string ErrInvalidKeyLength = "Invalid AES key length";
    private const string ErrInvalidNonceLength = "Invalid AES-GCM nonce length";
    private const string ErrInvalidTagLength = "Invalid AES-GCM tag length";
    private const string ErrEncryptFail = "AES-GCM encryption failed";
    private const string ErrDecryptFail = "AES-GCM decryption failed (authentication tag mismatch)";
    private const string ErrBufferTooSmall = "Destination buffer is too small";


    /// <summary>
    /// Encrypts plaintext using AES-256-GCM.
    /// </summary>
    /// <param name="key">The 32-byte AES key.</param>
    /// <param name="nonce">The 12-byte nonce (MUST be unique per key).</param>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="ciphertextDestination">The buffer to write the ciphertext to. Must be >= plaintext.Length.</param>
    /// <param name="tagDestination">The buffer to write the 16-byte authentication tag to.</param>
    /// <param name="associatedData">Optional associated data (can be ReadOnlySpan<byte>.Empty).</param>
    /// <exception cref="ArgumentNullException">Thrown if key, nonce, plaintext, ciphertextDestination, or tagDestination is implicitly null via default span.</exception>
    /// <exception cref="ArgumentException">Thrown for invalid key/nonce/tag lengths or if ciphertextDestination is too small.</exception>
    /// <exception cref="CryptographicException">Thrown for other cryptographic errors during encryption.</exception>
    /// <exception cref="ShieldChainStepException">Wrapped cryptographic exceptions.</exception>
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != Constants.AesKeySize) throw new ArgumentException(ErrInvalidKeyLength, nameof(key));
        if (nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException(ErrInvalidNonceLength, nameof(nonce));
        if (tagDestination.Length != Constants.AesGcmTagSize)
            throw new ArgumentException(ErrInvalidTagLength, nameof(tagDestination));
        if (ciphertextDestination.Length < plaintext.Length)
            throw new ArgumentException(ErrBufferTooSmall, nameof(ciphertextDestination));

        try
        {
            using AesGcm aesGcm = new(key, Constants.AesGcmTagSize);
            aesGcm.Encrypt(nonce, plaintext, ciphertextDestination, tagDestination, associatedData);
        }
        catch (CryptographicException cryptoEx)
        {
            throw new ShieldChainStepException(ErrEncryptFail, cryptoEx);
        }
        catch (Exception ex) 
        {
            throw new ShieldChainStepException(ErrEncryptFail, ex);
        }
    }

    /// <summary>
    /// Decrypts ciphertext using AES-256-GCM and verifies the authentication tag.
    /// </summary>
    /// <param name="key">The 32-byte AES key.</param>
    /// <param name="nonce">The 12-byte nonce used during encryption.</param>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="tag">The 16-byte authentication tag.</param>
    /// <param name="plaintextDestination">The buffer to write the decrypted plaintext to. Must be >= ciphertext.Length.</param>
    /// <param name="associatedData">Optional associated data (must match encryption AD).</param>
    /// <exception cref="ArgumentNullException">...</exception>
    /// <exception cref="ArgumentException">Thrown for invalid key/nonce/tag lengths or if plaintextDestination is too small.</exception>
    /// <exception cref="AuthenticationTagMismatchException">(Subclass of CryptographicException) Thrown if the tag is invalid.</exception>
    /// <exception cref="CryptographicException">Thrown for other cryptographic errors during decryption.</exception>
    /// <exception cref="ShieldChainStepException">Wrapped cryptographic exceptions.</exception>
    public static void Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintextDestination,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != Constants.AesKeySize) throw new ArgumentException(ErrInvalidKeyLength, nameof(key));
        if (nonce.Length != Constants.AesGcmNonceSize)
            throw new ArgumentException(ErrInvalidNonceLength, nameof(nonce));
        if (tag.Length != Constants.AesGcmTagSize) throw new ArgumentException(ErrInvalidTagLength, nameof(tag));
        if (plaintextDestination.Length < ciphertext.Length)
            throw new ArgumentException(ErrBufferTooSmall, nameof(plaintextDestination));

        try
        {
            using AesGcm aesGcm = new(key, Constants.AesGcmTagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintextDestination, associatedData);
        }
        catch (AuthenticationTagMismatchException authEx)
        {
            throw new ShieldChainStepException(ErrDecryptFail, authEx);
        }
        catch (CryptographicException cryptoEx) 
        {
            throw new ShieldChainStepException(ErrDecryptFail, cryptoEx); 
        }
        catch (Exception ex) 
        {
            throw new ShieldChainStepException(ErrDecryptFail, ex);
        }
    }


    // --- Convenience methods returning byte[] (less performant due to allocations) ---

    /// <summary>
    /// Encrypts plaintext using AES-256-GCM, allocating and returning ciphertext and tag.
    /// Less performant than the Span-based overload due to allocations.
    /// </summary>
    /// <returns>A tuple containing the ciphertext and the tag.</returns>
    public static (byte[] Ciphertext, byte[] Tag) EncryptAllocating(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[Constants.AesGcmTagSize];
        Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
        return (ciphertext, tag);
    }

    /// <summary>
    /// Decrypts ciphertext using AES-256-GCM, allocating and returning plaintext.
    /// Less performant than the Span-based overload due to allocations.
    /// </summary>
    /// <returns>The decrypted plaintext.</returns>
    public static byte[] DecryptAllocating(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        byte[] plaintext = new byte[ciphertext.Length];
        Decrypt(key, nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }
}