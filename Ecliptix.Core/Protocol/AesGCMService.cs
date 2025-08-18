using System.Security.Cryptography;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Core.Protocol;

public static class AesGcmService
{
    private const string ErrInvalidKeyLength = "Invalid AES key length";
    private const string ErrInvalidNonceLength = "Invalid AES-GCM nonce length";
    private const string ErrInvalidTagLength = "Invalid AES-GCM tag length";
    private const string ErrEncryptFail = "AES-GCM encryption failed";
    private const string ErrDecryptFail = "AES-GCM decryption failed (authentication tag mismatch)";
    private const string ErrBufferTooSmall = "Destination buffer is too small";

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
            throw new ProtocolChainStepException(ErrEncryptFail, cryptoEx);
        }
        catch (Exception ex)
        {
            throw new ProtocolChainStepException(ErrEncryptFail, ex);
        }
    }

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
            throw new ProtocolChainStepException(ErrDecryptFail, authEx);
        }
        catch (CryptographicException cryptoEx)
        {
            throw new ProtocolChainStepException(ErrDecryptFail, cryptoEx);
        }
        catch (Exception ex)
        {
            throw new ProtocolChainStepException(ErrDecryptFail, ex);
        }
    }

    public static (byte[] Ciphertext, byte[] Tag) EncryptAllocating(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        // Handle zero-length plaintext case
        if (plaintext.Length == 0)
        {
            using ScopedSecureMemory zeroTagMemory = ScopedSecureMemory.Allocate(Constants.AesGcmTagSize);
            Encrypt(key, nonce, plaintext, Span<byte>.Empty, zeroTagMemory.AsSpan(), associatedData);
            return (Array.Empty<byte>(), zeroTagMemory.AsSpan().ToArray());
        }

        using ScopedSecureMemory ciphertextMemory = ScopedSecureMemory.Allocate(plaintext.Length);
        using ScopedSecureMemory tagMemory = ScopedSecureMemory.Allocate(Constants.AesGcmTagSize);
        
        Encrypt(key, nonce, plaintext, ciphertextMemory.AsSpan(), tagMemory.AsSpan(), associatedData);
        
        return (ciphertextMemory.AsSpan().ToArray(), tagMemory.AsSpan().ToArray());
    }

    public static byte[] DecryptAllocating(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        // Handle zero-length ciphertext case
        if (ciphertext.Length == 0)
        {
            Decrypt(key, nonce, ciphertext, tag, Span<byte>.Empty, associatedData);
            return Array.Empty<byte>();
        }

        using var plaintextMemory = ScopedSecureMemory.Allocate(ciphertext.Length);
        Decrypt(key, nonce, ciphertext, tag, plaintextMemory.AsSpan(), associatedData);
        
        return plaintextMemory.AsSpan().ToArray();
    }
}