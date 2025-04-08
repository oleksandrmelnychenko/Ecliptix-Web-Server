using System.Security.Cryptography;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;

namespace ShieldProTests;

public class AesGcmServiceTests
{
    private static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(Constants.AesKeySize);
    private static byte[] GenerateNonce() => RandomNumberGenerator.GetBytes(Constants.AesGcmNonceSize);
    private static byte[] GenerateData(int size) => RandomNumberGenerator.GetBytes(size);

    private static byte[] CorruptBytes(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty) return Array.Empty<byte>();
        byte[] corrupted = input.ToArray();
        corrupted[0] ^= 0xFF;
        return corrupted;
    }

    [Fact]
    public void Encrypt_ValidInputs_SucceedsAndTagIsNotEmpty()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] associatedData = GenerateData(32);
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        byte[] emptyTag = new byte[Constants.AesGcmTagSize];

        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

        Assert.False(tag.SequenceEqual(emptyTag));
    }

    [Fact]
    public void Encrypt_EmptyPlaintext_SucceedsAndTagIsNotEmpty()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        ReadOnlySpan<byte> plaintext = ReadOnlySpan<byte>.Empty;
        byte[] associatedData = GenerateData(16);
        Span<byte> ciphertext = [];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        byte[] emptyTag = new byte[Constants.AesGcmTagSize];

        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

        Assert.False(tag.SequenceEqual(emptyTag));
    }

    [Fact]
    public void Encrypt_WithEmptyAssociatedData_Succeeds()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(64);
        ReadOnlySpan<byte> associatedData = ReadOnlySpan<byte>.Empty;
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        byte[] emptyTag = new byte[Constants.AesGcmTagSize];

        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

        Assert.False(tag.SequenceEqual(emptyTag));
    }

    [Fact]
    public void Encrypt_WithDefaultAssociatedData_Succeeds()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(64);
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        byte[] emptyTag = new byte[Constants.AesGcmTagSize];

        AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag);

        Assert.False(tag.SequenceEqual(emptyTag));
    }

    [Theory]
    [InlineData(Constants.AesKeySize - 1)]
    [InlineData(Constants.AesKeySize + 1)]
    [InlineData(0)]
    public void Encrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
    {
        byte[] key = GenerateData(invalidKeySize);
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[Constants.AesGcmTagSize];

        ArgumentException ex = Assert.Throws<ArgumentException>("key",
            () => AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Invalid AES key length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmNonceSize - 1)]
    [InlineData(Constants.AesGcmNonceSize + 1)]
    [InlineData(0)]
    public void Encrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateData(invalidNonceSize);
        byte[] plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[Constants.AesGcmTagSize];

        ArgumentException ex = Assert.Throws<ArgumentException>("nonce",
            () => AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Invalid AES-GCM nonce length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmTagSize - 1)]
    [InlineData(Constants.AesGcmTagSize + 1)]
    [InlineData(0)]
    public void Encrypt_ThrowsArgumentException_When_TagDestinationLengthIsInvalid(int invalidTagSize)
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[invalidTagSize];

        ArgumentException ex = Assert.Throws<ArgumentException>("tagDestination",
            () => AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Invalid AES-GCM tag length", ex.Message);
    }

    [Fact]
    public void Encrypt_ThrowsArgumentException_When_CiphertextDestinationIsTooSmall()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] ciphertext = new byte[plaintext.Length - 1];
        byte[] tag = new byte[Constants.AesGcmTagSize];

        ArgumentException ex = Assert.Throws<ArgumentException>("ciphertextDestination",
            () => AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
        Assert.Contains("Destination buffer is too small", ex.Message);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(0, 32)]
    [InlineData(128, 0)]
    [InlineData(256, 64)]
    [InlineData(1, 1)]
    public void Decrypt_ValidInputs_RecoversOriginalPlaintext(int plaintextSize, int adSize)
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] originalPlaintext = GenerateData(plaintextSize);
        byte[] associatedData = GenerateData(adSize);
        Span<byte> ciphertext = stackalloc byte[originalPlaintext.Length];
        Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
        Span<byte> decryptedPlaintext = stackalloc byte[originalPlaintext.Length];

        AesGcmService.Encrypt(key, nonce, originalPlaintext, ciphertext, tag, associatedData);
        AesGcmService.Decrypt(key, nonce, ciphertext, tag, decryptedPlaintext, associatedData);

        Assert.True(originalPlaintext.SequenceEqual(decryptedPlaintext.ToArray()));
    }

    [Fact]
    public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_TagIsInvalid()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] associatedData = GenerateData(32);
        (byte[] ciphertext, byte[] originalTag) =
            AesGcmService.EncryptAllocating(key, nonce, plaintext, associatedData);
        byte[] corruptedTag = CorruptBytes(originalTag);
        byte[] decryptedPlaintext = new byte[ciphertext.Length];

        ShieldChainStepException ex = Assert.Throws<ShieldChainStepException>(
            () => AesGcmService.Decrypt(key, nonce, ciphertext, corruptedTag, decryptedPlaintext, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void
        Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_CiphertextIsCorrupted()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] associatedData = GenerateData(32);
        (byte[] originalCiphertext, byte[] tag) =
            AesGcmService.EncryptAllocating(key, nonce, plaintext, associatedData);
        byte[] corruptedCiphertext = CorruptBytes(originalCiphertext);
        byte[] decryptedPlaintext = new byte[originalCiphertext.Length];

        ShieldChainStepException ex = Assert.Throws<ShieldChainStepException>(
            () => AesGcmService.Decrypt(key, nonce, corruptedCiphertext, tag, decryptedPlaintext, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void
        Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_AssociatedDataIsMismatched()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] originalAssociatedData = GenerateData(32);
        byte[] differentAssociatedData = CorruptBytes(originalAssociatedData);
        (byte[] ciphertext, byte[] tag) =
            AesGcmService.EncryptAllocating(key, nonce, plaintext, originalAssociatedData);
        byte[] decryptedPlaintext = new byte[ciphertext.Length];

        ShieldChainStepException ex = Assert.Throws<ShieldChainStepException>(
            () => AesGcmService.Decrypt(key, nonce, ciphertext, tag, decryptedPlaintext, differentAssociatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void
        Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_KeyIsIncorrect()
    {
        byte[] key1 = GenerateKey();
        byte[] key2 = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] associatedData = GenerateData(32);
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key1, nonce, plaintext, associatedData);
        byte[] decryptedPlaintext = new byte[ciphertext.Length];

        ShieldChainStepException ex = Assert.Throws<ShieldChainStepException>(
            () => AesGcmService.Decrypt(key2, nonce, ciphertext, tag, decryptedPlaintext, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void
        Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_NonceIsIncorrect()
    {
        byte[] key = GenerateKey();
        byte[] nonce1 = GenerateNonce();
        byte[] nonce2 = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] associatedData = GenerateData(32);
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce1, plaintext, associatedData);
        byte[] decryptedPlaintext = new byte[ciphertext.Length];

        ShieldChainStepException ex = Assert.Throws<ShieldChainStepException>(
            () => AesGcmService.Decrypt(key, nonce2, ciphertext, tag, decryptedPlaintext, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(Constants.AesKeySize - 1)]
    [InlineData(Constants.AesKeySize + 1)]
    [InlineData(0)]
    public void Decrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
    {
        byte[] key = GenerateData(invalidKeySize);
        byte[] nonce = GenerateNonce();
        byte[] ciphertext = GenerateData(128);
        byte[] tag = Helpers.GenerateSecureRandomTag(Constants.AesGcmTagSize);
        byte[] plaintext = new byte[ciphertext.Length];

        ArgumentException ex = Assert.Throws<ArgumentException>("key",
            () => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
        Assert.Contains("Invalid AES key length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmNonceSize - 1)]
    [InlineData(Constants.AesGcmNonceSize + 1)]
    [InlineData(0)]
    public void Decrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateData(invalidNonceSize);
        byte[] ciphertext = GenerateData(128);
        byte[] tag = Helpers.GenerateSecureRandomTag(Constants.AesGcmTagSize);
        byte[] plaintext = new byte[ciphertext.Length];

        ArgumentException ex = Assert.Throws<ArgumentException>("nonce",
            () => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
        Assert.Contains("Invalid AES-GCM nonce length", ex.Message);
    }

    [Theory]
    [InlineData(Constants.AesGcmTagSize - 1)]
    [InlineData(Constants.AesGcmTagSize + 1)]
    [InlineData(0)]
    public void Decrypt_ThrowsArgumentException_When_TagLengthIsInvalid(int invalidTagSize)
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] ciphertext = GenerateData(128);
        byte[] tag = GenerateData(invalidTagSize);
        byte[] plaintext = new byte[ciphertext.Length];

        ArgumentException ex = Assert.Throws<ArgumentException>("tag",
            () => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
        Assert.Contains("Invalid AES-GCM tag length", ex.Message);
    }

    [Fact]
    public void Decrypt_ThrowsArgumentException_When_PlaintextDestinationIsTooSmall()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, GenerateData(128));
        byte[] plaintextDestination = new byte[ciphertext.Length - 1];

        ArgumentException ex = Assert.Throws<ArgumentException>("plaintextDestination",
            () => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintextDestination));
        Assert.Contains("Destination buffer is too small", ex.Message);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(0, 32)]
    [InlineData(128, 0)]
    [InlineData(256, 64)]
    public void EncryptAllocating_DecryptAllocating_RoundtripSucceeds(int plaintextSize, int adSize)
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] originalPlaintext = GenerateData(plaintextSize);
        byte[] associatedData = GenerateData(adSize);

        (byte[] ciphertext, byte[] tag) =
            AesGcmService.EncryptAllocating(key, nonce, originalPlaintext, associatedData);
        byte[] decryptedPlaintext = AesGcmService.DecryptAllocating(key, nonce, ciphertext, tag, associatedData);

        Assert.Equal(originalPlaintext, decryptedPlaintext);
        Assert.Equal(Constants.AesGcmTagSize, tag.Length);
        Assert.Equal(originalPlaintext.Length, ciphertext.Length);
    }

    [Fact]
    public void DecryptAllocating_ThrowsShieldChainStepException_When_TagIsInvalid()
    {
        byte[] key = GenerateKey();
        byte[] nonce = GenerateNonce();
        byte[] plaintext = GenerateData(128);
        byte[] associatedData = GenerateData(32);
        (byte[] ciphertext, byte[] originalTag) =
            AesGcmService.EncryptAllocating(key, nonce, plaintext, associatedData);
        byte[] corruptedTag = CorruptBytes(originalTag);

        ShieldChainStepException ex = Assert.Throws<ShieldChainStepException>(
            () => AesGcmService.DecryptAllocating(key, nonce, ciphertext, corruptedTag, associatedData));

        Assert.NotNull(ex.InnerException);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
        Assert.Contains("authentication tag mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}