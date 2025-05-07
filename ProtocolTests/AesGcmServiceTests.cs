using System.Security.Cryptography;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Utilities;

// MSTest namespace
// Ensure this namespace is correct

// For Constants, ShieldChainStepException, Helpers

namespace ProtocolTests // Your test project namespace
{
    [TestClass] // Use MSTest attribute
    public class AesGcmServiceTests // No IDisposable needed unless setup/teardown per test is complex
    {
        // Optional: TestContext for logging output
        public TestContext TestContext { get; set; } = null!; // Non-null asserted by runner

        // --- ClassInitialize for SodiumCore.Init (runs once) ---
        [ClassInitialize]
        public static void ClassInit(TestContext context) // Needs TestContext parameter
        {
            try
            {
                Sodium.SodiumCore.Init();
                 context.WriteLine("Sodium Initialized for AesGcmServiceTests."); // Use TestContext for output
            }
            catch (Exception ex)
            {
                context.WriteLine($"FATAL Sodium Init: {ex.Message}");
                throw; // Fail initialization
            }
        }

        // --- Test Data Generation Helpers ---
        // (Remain the same)
        private static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(Constants.AesKeySize);
        private static byte[] GenerateNonce() => RandomNumberGenerator.GetBytes(Constants.AesGcmNonceSize);
        private static byte[] GenerateData(int size) => RandomNumberGenerator.GetBytes(size);
        private static byte[] CorruptBytes(ReadOnlySpan<byte> input)
        {
            if (input.IsEmpty) return Array.Empty<byte>();
            var corrupted = input.ToArray();
            corrupted[0] ^= 0xFF;
            return corrupted;
        }

        // --- Encryption Tests ---

        [TestMethod] // Use MSTest attribute
        public void Encrypt_ValidInputs_SucceedsAndTagIsNotEmpty()
        {
            // Arrange
            var key = GenerateKey();
            var nonce = GenerateNonce();
            var plaintext = GenerateData(128);
            var associatedData = GenerateData(32);
            Span<byte> ciphertext = stackalloc byte[plaintext.Length];
            Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
            var emptyTag = new byte[Constants.AesGcmTagSize];

            // Act
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

            // Assert
            // Use CollectionAssert for sequence inequality (or !SequenceEqual)
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray(), "Generated tag should not be all zeros.");
            // Or: Assert.IsFalse(tag.SequenceEqual(emptyTag), "Generated tag should not be all zeros.");
        }

        [TestMethod]
        public void Encrypt_EmptyPlaintext_SucceedsAndTagIsNotEmpty()
        {
            // Arrange
            var key = GenerateKey();
            var nonce = GenerateNonce();
            var plaintext = ReadOnlySpan<byte>.Empty;
            var associatedData = GenerateData(16);
            Span<byte> ciphertext = stackalloc byte[0];
            Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
            var emptyTag = new byte[Constants.AesGcmTagSize];

            // Act
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

            // Assert
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray());
            // Or: Assert.IsFalse(tag.SequenceEqual(emptyTag));
        }

        [TestMethod]
        public void Encrypt_WithEmptyAssociatedData_Succeeds()
        {
            // Arrange
            var key = GenerateKey();
            var nonce = GenerateNonce();
            var plaintext = GenerateData(64);
            var associatedData = ReadOnlySpan<byte>.Empty;
            Span<byte> ciphertext = stackalloc byte[plaintext.Length];
            Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
            var emptyTag = new byte[Constants.AesGcmTagSize];

            // Act
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);

            // Assert
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray());
        }

        [TestMethod]
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
            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag); // Uses default AD

            // Assert
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray());
        }

        // --- Encryption Error Condition Tests ---

        [TestMethod] // Use TestMethod
        // Use DataRow for parameterized tests
        [DataRow(Constants.AesKeySize - 1)]
        [DataRow(Constants.AesKeySize + 1)]
        [DataRow(0)]
        public void Encrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
        {
            // Arrange
            var key = GenerateData(invalidKeySize);
            var nonce = GenerateNonce();
            var plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[Constants.AesGcmTagSize];

            // Act & Assert
            // Use Assert.ThrowsException and check properties
            var ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
            StringAssert.Contains(ex.Message, "Invalid AES key length"); // Use StringAssert
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(Constants.AesGcmNonceSize - 1)]
        [DataRow(Constants.AesGcmNonceSize + 1)]
        [DataRow(0)]
        public void Encrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
        {
            // Arrange
            var key = GenerateKey();
            var nonce = GenerateData(invalidNonceSize);
            var plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[Constants.AesGcmTagSize];

            // Act & Assert
            var ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
            StringAssert.Contains(ex.Message, "Invalid AES-GCM nonce length");
            Assert.AreEqual("nonce", ex.ParamName);
        }

         [TestMethod]
         [DataRow(Constants.AesGcmTagSize - 1)]
         [DataRow(Constants.AesGcmTagSize + 1)]
         [DataRow(0)]
         public void Encrypt_ThrowsArgumentException_When_TagDestinationLengthIsInvalid(int invalidTagSize)
        {
            // Arrange
            var key = GenerateKey();
            var nonce = GenerateNonce();
            var plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[invalidTagSize];

            // Act & Assert
            var ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
            StringAssert.Contains(ex.Message, "Invalid AES-GCM tag length");
            Assert.AreEqual("tagDestination", ex.ParamName);
        }

        [TestMethod]
        public void Encrypt_ThrowsArgumentException_When_CiphertextDestinationIsTooSmall()
        {
            // Arrange
            var key = GenerateKey();
            var nonce = GenerateNonce();
            var plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length - 1]; // Too small
            byte[] tag = new byte[Constants.AesGcmTagSize];

            // Act & Assert
            var ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
            StringAssert.Contains(ex.Message, "Destination buffer is too small");
            Assert.AreEqual("ciphertextDestination", ex.ParamName);
        }

        // --- Decryption Tests (Roundtrip and Success Cases) ---

        [TestMethod]
        [DataRow(0, 0)]
        [DataRow(0, 32)]
        [DataRow(128, 0)]
        [DataRow(256, 64)]
        [DataRow(1, 1)]
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
            // Use CollectionAssert for sequence equality
            CollectionAssert.AreEqual(originalPlaintext, decryptedPlaintext.ToArray(), "Decrypted plaintext mismatch.");
        }

        // --- Decryption Failure Tests ---

        [TestMethod]
        public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_TagIsInvalid()
        {
            // Arrange
            var key = GenerateKey(); var nonce = GenerateNonce(); var plaintext = GenerateData(128); var ad = GenerateData(32);
            (byte[] ciphertext, byte[] originalTag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, ad);
            var corruptedTag = CorruptBytes(originalTag);
            byte[] decryptedPlaintext = new byte[ciphertext.Length]; // Use byte[] for lambda

            // Act & Assert
            var ex = Assert.ThrowsException<ShieldChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, corruptedTag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            // Use Assert.IsInstanceOfType
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

         [TestMethod]
        public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_CiphertextIsCorrupted()
        {
             // Arrange
            var key = GenerateKey(); var nonce = GenerateNonce(); var plaintext = GenerateData(128); var ad = GenerateData(32);
            (byte[] originalCiphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, ad);
            var corruptedCiphertext = CorruptBytes(originalCiphertext);
            byte[] decryptedPlaintext = new byte[originalCiphertext.Length];

            // Act & Assert
            var ex = Assert.ThrowsException<ShieldChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce, corruptedCiphertext, tag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

         [TestMethod]
        public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_AssociatedDataIsMismatched()
        {
            // Arrange
            var key = GenerateKey(); var nonce = GenerateNonce(); var plaintext = GenerateData(128);
            var originalAD = GenerateData(32); var differentAD = CorruptBytes(originalAD);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, originalAD);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            // Act & Assert
            var ex = Assert.ThrowsException<ShieldChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, tag, decryptedPlaintext, differentAD));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_KeyIsIncorrect()
        {
            // Arrange
            var key1 = GenerateKey(); var key2 = GenerateKey(); var nonce = GenerateNonce(); var plaintext = GenerateData(128); var ad = GenerateData(32);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key1, nonce, plaintext, ad);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            // Act & Assert
            var ex = Assert.ThrowsException<ShieldChainStepException>(() =>
                AesGcmService.Decrypt(key2, nonce, ciphertext, tag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        public void Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_NonceIsIncorrect()
        {
            // Arrange
            var key = GenerateKey(); var nonce1 = GenerateNonce(); var nonce2 = GenerateNonce(); var plaintext = GenerateData(128); var ad = GenerateData(32);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce1, plaintext, ad);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            // Act & Assert
            var ex = Assert.ThrowsException<ShieldChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce2, ciphertext, tag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        // --- Decryption Error Condition Tests (Arguments) ---

        [TestMethod]
        [DataRow(Constants.AesKeySize - 1)]
        [DataRow(Constants.AesKeySize + 1)]
        [DataRow(0)]
        public void Decrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
        {
            // Arrange
             var key = GenerateData(invalidKeySize); var nonce = GenerateNonce(); var ciphertext = GenerateData(128); var tag = GenerateData(Constants.AesGcmTagSize); // Use helper
             byte[] plaintext = new byte[ciphertext.Length];
             // Act & Assert
             var ex = Assert.ThrowsException<ArgumentException>(() => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
             StringAssert.Contains(ex.Message, "Invalid AES key length");
             Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(Constants.AesGcmNonceSize - 1)]
        [DataRow(Constants.AesGcmNonceSize + 1)]
        [DataRow(0)]
        public void Decrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
        {
             // Arrange
              var key = GenerateKey(); var nonce = GenerateData(invalidNonceSize); var ciphertext = GenerateData(128); var tag = GenerateData(Constants.AesGcmTagSize);
              byte[] plaintext = new byte[ciphertext.Length];
             // Act & Assert
             var ex = Assert.ThrowsException<ArgumentException>(() => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
             StringAssert.Contains(ex.Message, "Invalid AES-GCM nonce length");
             Assert.AreEqual("nonce", ex.ParamName);
        }

         [TestMethod]
         [DataRow(Constants.AesGcmTagSize - 1)]
         [DataRow(Constants.AesGcmTagSize + 1)]
         [DataRow(0)]
         public void Decrypt_ThrowsArgumentException_When_TagLengthIsInvalid(int invalidTagSize)
         {
             // Arrange
             var key = GenerateKey(); var nonce = GenerateNonce(); var ciphertext = GenerateData(128); var tag = GenerateData(invalidTagSize);
             byte[] plaintext = new byte[ciphertext.Length];
            // Act & Assert
             var ex = Assert.ThrowsException<ArgumentException>(() => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
             StringAssert.Contains(ex.Message, "Invalid AES-GCM tag length");
             Assert.AreEqual("tag", ex.ParamName);
         }

         [TestMethod]
         public void Decrypt_ThrowsArgumentException_When_PlaintextDestinationIsTooSmall()
         {
             // Arrange
             var key = GenerateKey(); var nonce = GenerateNonce();
             (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, GenerateData(128));
             byte[] plaintextDestination = new byte[ciphertext.Length - 1]; // Too small
             // Act & Assert
             var ex = Assert.ThrowsException<ArgumentException>(() => AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintextDestination));
             StringAssert.Contains(ex.Message, "Destination buffer is too small");
             Assert.AreEqual("plaintextDestination", ex.ParamName);
         }

        // --- Allocating Helper Method Tests ---

        [TestMethod]
        [DataRow(0, 0)]
        [DataRow(0, 32)]
        [DataRow(128, 0)]
        [DataRow(256, 64)]
        public void EncryptAllocating_DecryptAllocating_RoundtripSucceeds(int plaintextSize, int adSize)
        {
             // Arrange
             var key = GenerateKey(); var nonce = GenerateNonce(); var originalPlaintext = GenerateData(plaintextSize); var ad = GenerateData(adSize);
            // Act
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, originalPlaintext, ad);
            byte[] decryptedPlaintext = AesGcmService.DecryptAllocating(key, nonce, ciphertext, tag, ad);
            // Assert
            CollectionAssert.AreEqual(originalPlaintext, decryptedPlaintext); // Use CollectionAssert
            Assert.AreEqual(Constants.AesGcmTagSize, tag.Length);
            Assert.AreEqual(originalPlaintext.Length, ciphertext.Length);
        }

         [TestMethod]
         public void DecryptAllocating_ThrowsShieldChainStepException_When_TagIsInvalid()
         {
             // Arrange
             var key = GenerateKey(); var nonce = GenerateNonce(); var plaintext = GenerateData(128); var ad = GenerateData(32);
             (byte[] ciphertext, byte[] originalTag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, ad);
             var corruptedTag = CorruptBytes(originalTag);
            // Act & Assert
             var ex = Assert.ThrowsException<ShieldChainStepException>(() => AesGcmService.DecryptAllocating(key, nonce, ciphertext, corruptedTag, ad));
             Assert.IsNotNull(ex.InnerException);
             Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
             StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
         }
    }
}