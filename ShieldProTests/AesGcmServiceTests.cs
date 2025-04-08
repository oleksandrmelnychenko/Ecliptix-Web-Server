using System;
using System.Linq;
using System.Security.Cryptography;
using Ecliptix.Core.Protocol; // Ensure this namespace is correct
using Ecliptix.Core.Protocol.Utilities; // For Constants, ShieldChainStepException
using Xunit;

namespace ShieldProTests; // Or your test project namespace

public class AesGcmServiceTests
{
    // --- Test Data Generation Helpers ---

    private static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(Constants.AesKeySize);
    private static byte[] GenerateNonce() => RandomNumberGenerator.GetBytes(Constants.AesGcmNonceSize);
    private static byte[] GenerateData(int size) => RandomNumberGenerator.GetBytes(size);

    private static byte[] CorruptBytes(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty) return Array.Empty<byte>();
        var corrupted = input.ToArray(); // Clone
        corrupted[0] ^= 0xFF; // Flip the first byte
        return corrupted;
    }

    // --- Encryption Tests ---

    [Fact]
    public void Encrypt_ValidInputs_SucceedsAndTagIsNotEmpty()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        var associatedData = GenerateData(32);
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        var emptyTag = new byte[Constants.AesGcmTagSize]; // For comparison

        // Act
        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

        // Assert
        Assert.False(tag.SequenceEqual(emptyTag), "Generated tag should not be all zeros.");
        // Further validation requires decryption
    }

    [Fact]
    public void Encrypt_EmptyPlaintext_SucceedsAndTagIsNotEmpty()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = ReadOnlySpan<byte>.Empty; // Use ReadOnlySpan directly
        var associatedData = GenerateData(16);
        Span<byte> ciphertext = stackalloc byte[0]; // size 0
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        var emptyTag = new byte[Constants.AesGcmTagSize];

        // Act
        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

        // Assert
        Assert.False(tag.SequenceEqual(emptyTag), "Generated tag should not be all zeros even for empty plaintext.");
    }

    [Fact]
    public void Encrypt_WithEmptyAssociatedData_Succeeds()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(64);
        var associatedData = ReadOnlySpan<byte>.Empty; // Use ReadOnlySpan directly
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        var emptyTag = new byte[Constants.AesGcmTagSize];

        // Act
        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

        // Assert
        Assert.False(tag.SequenceEqual(emptyTag));
    }

    [Fact]
    public void Encrypt_WithDefaultAssociatedData_Succeeds()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(64);
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        var emptyTag = new byte[Constants.AesGcmTagSize];

        // Act
        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag); // Use default AD

        // Assert
        Assert.False(tag.SequenceEqual(emptyTag));
    }

    // --- Encryption Error Condition Tests ---

    [Theory]
    [InlineData(Constants.AesKeySize - 1)] // Too short
    [InlineData(Constants.AesKeySize + 1)] // Too long
    [InlineData(0)]                     // Zero length
    public void Encrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
    {
        // Arrange
        var key = GenerateData(invalidKeySize);
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        // Use byte[] for buffers when testing argument validation errors occurring before buffer usage
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[Constants.AesGcmTagSize];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("key", () => // Check ParamName directly
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Invalid AES key length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmNonceSize - 1)] // Too short
    [InlineData(Constants.AesGcmNonceSize + 1)] // Too long
    [InlineData(0)]                     // Zero length
    public void Encrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateData(invalidNonceSize);
        var plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[Constants.AesGcmTagSize];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("nonce", () =>
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Invalid AES-GCM nonce length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmTagSize - 1)] // Too short
    [InlineData(Constants.AesGcmTagSize + 1)] // Too long
    [InlineData(0)]                     // Zero length
    public void Encrypt_ThrowsArgumentException_When_TagDestinationLengthIsInvalid(int invalidTagSize)
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[invalidTagSize]; // Invalid tag destination size

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("tagDestination", () =>
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Invalid AES-GCM tag length", ex.Message);
    }

    [Fact]
    public void Encrypt_ThrowsArgumentException_When_CiphertextDestinationIsTooSmall()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length - 1]; // Too small
        byte[] tag = new byte[Constants.AesGcmTagSize];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("ciphertextDestination", () =>
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Destination buffer is too small", ex.Message);
    }

    // --- Decryption Tests (Roundtrip and Success Cases) ---

    [Theory]
    [InlineData(0, 0)]    // Empty plaintext, empty AD
    [InlineData(0, 32)]   // Empty plaintext, with AD
    [InlineData(128, 0)]  // With plaintext, empty AD
    [InlineData(256, 64)] // With plaintext, with AD
    [InlineData(1, 1)]    // Minimal data
    public void Decrypt_ValidInputs_RecoversOriginalPlaintext(int plaintextSize, int adSize)
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var originalPlaintext = GenerateData(plaintextSize);
        var associatedData = GenerateData(adSize);
        Span<byte> ciphertext = stackalloc byte[originalPlaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        Span<byte> decryptedPlaintext = stackalloc byte[originalPlaintext.Length];

        AesGcmService.Encrypt(key, nonce, originalPlaintext, ciphertext, tag, associatedData);

        // Act
        AesGcmService.Decrypt(key, nonce, ciphertext, tag, decryptedPlaintext, associatedData);

        // Assert
        Assert.True(originalPlaintext.SequenceEqual(decryptedPlaintext.ToArray()), "Decrypted plaintext mismatch.");
    }

    // --- Decryption Failure Tests ---

    [Fact]
    public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_TagIsInvalid()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        var associatedData = GenerateData(32);
        // Use allocating helper for setup convenience
        (byte[] ciphertext, byte[] originalTag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, associatedData);
        var corruptedTag = CorruptBytes(originalTag);
        // Use stackalloc for destination as operation fails before writing much
        var decryptedPlaintext = new byte[ciphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ShieldChainStepException>(() =>
            AesGcmService.Decrypt(key, nonce, ciphertext, corruptedTag, decryptedPlaintext, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_CiphertextIsCorrupted()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        var associatedData = GenerateData(32);
        // Use allocating helper for setup convenience
        (byte[] originalCiphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, associatedData);
        var corruptedCiphertext = CorruptBytes(originalCiphertext);
        var decryptedPlaintext = new byte[originalCiphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ShieldChainStepException>(() =>
            AesGcmService.Decrypt(key, nonce, corruptedCiphertext, tag, decryptedPlaintext, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException); // Tampering results in tag mismatch
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_AssociatedDataIsMismatched()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        var originalAssociatedData = GenerateData(32);
        var differentAssociatedData = CorruptBytes(originalAssociatedData);
        // Use allocating helper for setup convenience
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, originalAssociatedData);
        byte[] decryptedPlaintext =  new byte[ciphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ShieldChainStepException>(() =>
            AesGcmService.Decrypt(key, nonce, ciphertext, tag, decryptedPlaintext, differentAssociatedData)); // Use different AD

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException); // AD mismatch results in tag mismatch
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_KeyIsIncorrect()
    {
        // Arrange
        var key1 = GenerateKey();
        var key2 = GenerateKey(); // Different key
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        var associatedData = GenerateData(32);
        // Use allocating helper for setup convenience
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key1, nonce, plaintext, associatedData); // Encrypt with key1
        var decryptedPlaintext = new byte[ciphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ShieldChainStepException>(() =>
            AesGcmService.Decrypt(key2, nonce, ciphertext, tag, decryptedPlaintext, associatedData)); // Decrypt with key2

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException); // Wrong key results in tag mismatch
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_NonceIsIncorrect()
    {
        // Arrange
        var key = GenerateKey();
        var nonce1 = GenerateNonce();
        var nonce2 = GenerateNonce(); // Different nonce
        var plaintext = GenerateData(128);
        var associatedData = GenerateData(32);
        // Use allocating helper for setup convenience
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce1, plaintext, associatedData); // Encrypt with nonce1
        var decryptedPlaintext = new byte[ciphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ShieldChainStepException>(() =>
            AesGcmService.Decrypt(key, nonce2, ciphertext, tag, decryptedPlaintext, associatedData)); // Decrypt with nonce2

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException); // Wrong nonce results in tag mismatch
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // --- Decryption Error Condition Tests (Arguments) ---

    [Theory]
    [InlineData(Constants.AesKeySize - 1)] // Too short
    [InlineData(Constants.AesKeySize + 1)] // Too long
    [InlineData(0)]                     // Zero length
    public void Decrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
    {
        // Arrange
        var key = GenerateData(invalidKeySize);
        var nonce = GenerateNonce();
        var ciphertext = GenerateData(128); // Dummy data
        var tag = Helpers.GenerateSecureRandomTag(Constants.AesGcmTagSize);
        byte[] plaintext = new byte[ciphertext.Length]; // Use byte[] for buffer validation tests

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("key", () =>
            AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
        Assert.Contains("Invalid AES key length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmNonceSize - 1)] // Too short
    [InlineData(Constants.AesGcmNonceSize + 1)] // Too long
    [InlineData(0)]                     // Zero length
    public void Decrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateData(invalidNonceSize);
        var ciphertext = GenerateData(128);
        var tag = Helpers.GenerateSecureRandomTag(Constants.AesGcmTagSize);
        byte[] plaintext = new byte[ciphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("nonce", () =>
            AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
        Assert.Contains("Invalid AES-GCM nonce length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmTagSize - 1)] // Too short
    [InlineData(Constants.AesGcmTagSize + 1)] // Too long
    [InlineData(0)]                     // Zero length
    public void Decrypt_ThrowsArgumentException_When_TagLengthIsInvalid(int invalidTagSize)
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var ciphertext = GenerateData(128);
        var tag = GenerateData(invalidTagSize); // Invalid tag size
        byte[] plaintext = new byte[ciphertext.Length];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("tag", () =>
            AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
        Assert.Contains("Invalid AES-GCM tag length", ex.Message);
    }

    [Fact]
    public void Decrypt_ThrowsArgumentException_When_PlaintextDestinationIsTooSmall()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        // Encrypt some data to get valid ciphertext/tag
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, GenerateData(128));
        // Create a destination buffer that's too small
        byte[] plaintextDestination = new byte[ciphertext.Length - 1];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>("plaintextDestination", () =>
            AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintextDestination));
        Assert.Contains("Destination buffer is too small", ex.Message);
    }

    // --- Allocating Helper Method Tests ---

    [Theory]
    [InlineData(0, 0)]    // Empty plaintext, empty AD
    [InlineData(0, 32)]   // Empty plaintext, with AD
    [InlineData(128, 0)]  // With plaintext, empty AD
    [InlineData(256, 64)] // With plaintext, with AD
    public void EncryptAllocating_DecryptAllocating_RoundtripSucceeds(int plaintextSize, int adSize)
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var originalPlaintext = GenerateData(plaintextSize);
        var associatedData = GenerateData(adSize);

        // Act
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, originalPlaintext, associatedData);
        byte[] decryptedPlaintext = AesGcmService.DecryptAllocating(key, nonce, ciphertext, tag, associatedData);

        // Assert
        Assert.Equal(originalPlaintext, decryptedPlaintext);
        Assert.Equal(Constants.AesGcmTagSize, tag.Length);
        Assert.Equal(originalPlaintext.Length, ciphertext.Length);
    }

    [Fact]
    public void DecryptAllocating_ThrowsShieldChainStepException_When_TagIsInvalid()
    {
        // Arrange
        var key = GenerateKey();
        var nonce = GenerateNonce();
        var plaintext = GenerateData(128);
        var associatedData = GenerateData(32);
        (byte[] ciphertext, byte[] originalTag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, associatedData);
        var corruptedTag = CorruptBytes(originalTag);

        // Act & Assert
        var ex = Assert.Throws<ShieldChainStepException>(() =>
            AesGcmService.DecryptAllocating(key, nonce, ciphertext, corruptedTag, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}