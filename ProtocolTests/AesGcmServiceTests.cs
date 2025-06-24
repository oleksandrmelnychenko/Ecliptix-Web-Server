using System.Security.Cryptography;
using Ecliptix.Core.Protocol;
using Ecliptix.Domain.Utilities;

namespace ProtocolTests
{
    [TestClass]
    public class AesGcmServiceTests
    {
        public TestContext TestContext { get; set; } = null!;

        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            try
            {
                Sodium.SodiumCore.Init();
                context.WriteLine("Sodium Initialized for AesGcmServiceTests.");
            }
            catch (Exception ex)
            {
                context.WriteLine($"FATAL Sodium Init: {ex.Message}");
                throw;
            }
        }

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


        [TestMethod]
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

            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray(), "Generated tag should not be all zeros.");
        }

        [TestMethod]
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
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray());
        }

        [TestMethod]
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
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray());
        }

        [TestMethod]
        public void Encrypt_WithDefaultAssociatedData_Succeeds()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(64);
            Span<byte> ciphertext = stackalloc byte[plaintext.Length];
            Span<byte> tag = stackalloc byte[Constants.AesGcmTagSize];
            byte[] emptyTag = new byte[Constants.AesGcmTagSize];

            AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag);
            CollectionAssert.AreNotEqual(emptyTag, tag.ToArray());
        }

        [TestMethod]
        [DataRow(Constants.AesKeySize - 1)]
        [DataRow(Constants.AesKeySize + 1)]
        [DataRow(0)]
        public void Encrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
        {
            byte[] key = GenerateData(invalidKeySize);
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[Constants.AesGcmTagSize];

            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
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
            byte[] key = GenerateKey();
            byte[] nonce = GenerateData(invalidNonceSize);
            byte[] plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[Constants.AesGcmTagSize];

            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
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
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[invalidTagSize];

            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
            StringAssert.Contains(ex.Message, "Invalid AES-GCM tag length");
            Assert.AreEqual("tagDestination", ex.ParamName);
        }

        [TestMethod]
        public void Encrypt_ThrowsArgumentException_When_CiphertextDestinationIsTooSmall()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ciphertext = new byte[plaintext.Length - 1]; // Too small
            byte[] tag = new byte[Constants.AesGcmTagSize];

            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Encrypt(key, nonce, plaintext, ciphertext, tag));
            StringAssert.Contains(ex.Message, "Destination buffer is too small");
            Assert.AreEqual("ciphertextDestination", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 0)]
        [DataRow(0, 32)]
        [DataRow(128, 0)]
        [DataRow(256, 64)]
        [DataRow(1, 1)]
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
            CollectionAssert.AreEqual(originalPlaintext, decryptedPlaintext.ToArray(), "Decrypted plaintext mismatch.");
        }

        [TestMethod]
        public void
            Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_TagIsInvalid()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ad = GenerateData(32);
            (byte[] ciphertext, byte[] originalTag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, ad);
            byte[] corruptedTag = CorruptBytes(originalTag);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            ProtocolChainStepException ex = Assert.ThrowsException<ProtocolChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, corruptedTag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        public void
            Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_CiphertextIsCorrupted()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ad = GenerateData(32);
            (byte[] originalCiphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, ad);
            byte[] corruptedCiphertext = CorruptBytes(originalCiphertext);
            byte[] decryptedPlaintext = new byte[originalCiphertext.Length];

            ProtocolChainStepException ex = Assert.ThrowsException<ProtocolChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce, corruptedCiphertext, tag, decryptedPlaintext, ad));
            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        public void
            Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_AssociatedDataIsMismatched()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] originalAD = GenerateData(32);
            byte[] differentAD = CorruptBytes(originalAD);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, originalAD);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            ProtocolChainStepException ex = Assert.ThrowsException<ProtocolChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, tag, decryptedPlaintext, differentAD));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        public void
            Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_KeyIsIncorrect()
        {
            byte[] key1 = GenerateKey();
            byte[] key2 = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ad = GenerateData(32);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key1, nonce, plaintext, ad);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            ProtocolChainStepException ex = Assert.ThrowsException<ProtocolChainStepException>(() =>
                AesGcmService.Decrypt(key2, nonce, ciphertext, tag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        public void
            Decrypt_ThrowsShieldChainStepException_With_InnerAuthenticationTagMismatchException_When_NonceIsIncorrect()
        {
            byte[] key = GenerateKey();
            byte[] nonce1 = GenerateNonce();
            byte[] nonce2 = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ad = GenerateData(32);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce1, plaintext, ad);
            byte[] decryptedPlaintext = new byte[ciphertext.Length];

            ProtocolChainStepException ex = Assert.ThrowsException<ProtocolChainStepException>(() =>
                AesGcmService.Decrypt(key, nonce2, ciphertext, tag, decryptedPlaintext, ad));

            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }

        [TestMethod]
        [DataRow(Constants.AesKeySize - 1)]
        [DataRow(Constants.AesKeySize + 1)]
        [DataRow(0)]
        public void Decrypt_ThrowsArgumentException_When_KeyLengthIsInvalid(int invalidKeySize)
        {
            byte[] key = GenerateData(invalidKeySize);
            byte[] nonce = GenerateNonce();
            byte[] ciphertext = GenerateData(128);
            byte[] tag = GenerateData(Constants.AesGcmTagSize);
            byte[] plaintext = new byte[ciphertext.Length];
            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
            StringAssert.Contains(ex.Message, "Invalid AES key length");
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        [DataRow(Constants.AesGcmNonceSize - 1)]
        [DataRow(Constants.AesGcmNonceSize + 1)]
        [DataRow(0)]
        public void Decrypt_ThrowsArgumentException_When_NonceLengthIsInvalid(int invalidNonceSize)
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateData(invalidNonceSize);
            byte[] ciphertext = GenerateData(128);
            byte[] tag = GenerateData(Constants.AesGcmTagSize);
            byte[] plaintext = new byte[ciphertext.Length];
            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
            StringAssert.Contains(ex.Message, "Invalid AES-GCM nonce length");
            Assert.AreEqual("nonce", ex.ParamName);
        }

        [TestMethod]
        [DataRow(Constants.AesGcmTagSize - 1)]
        [DataRow(Constants.AesGcmTagSize + 1)]
        [DataRow(0)]
        public void Decrypt_ThrowsArgumentException_When_TagLengthIsInvalid(int invalidTagSize)
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] ciphertext = GenerateData(128);
            byte[] tag = GenerateData(invalidTagSize);
            byte[] plaintext = new byte[ciphertext.Length];
            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintext));
            StringAssert.Contains(ex.Message, "Invalid AES-GCM tag length");
            Assert.AreEqual("tag", ex.ParamName);
        }

        [TestMethod]
        public void Decrypt_ThrowsArgumentException_When_PlaintextDestinationIsTooSmall()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, GenerateData(128));
            byte[] plaintextDestination = new byte[ciphertext.Length - 1];
            ArgumentException ex = Assert.ThrowsException<ArgumentException>(() =>
                AesGcmService.Decrypt(key, nonce, ciphertext, tag, plaintextDestination));
            StringAssert.Contains(ex.Message, "Destination buffer is too small");
            Assert.AreEqual("plaintextDestination", ex.ParamName);
        }

        [TestMethod]
        [DataRow(0, 0)]
        [DataRow(0, 32)]
        [DataRow(128, 0)]
        [DataRow(256, 64)]
        public void EncryptAllocating_DecryptAllocating_RoundtripSucceeds(int plaintextSize, int adSize)
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] originalPlaintext = GenerateData(plaintextSize);
            byte[] ad = GenerateData(adSize);
            (byte[] ciphertext, byte[] tag) = AesGcmService.EncryptAllocating(key, nonce, originalPlaintext, ad);
            byte[] decryptedPlaintext = AesGcmService.DecryptAllocating(key, nonce, ciphertext, tag, ad);
            CollectionAssert.AreEqual(originalPlaintext, decryptedPlaintext);
            Assert.AreEqual(Constants.AesGcmTagSize, tag.Length);
            Assert.AreEqual(originalPlaintext.Length, ciphertext.Length);
        }

        [TestMethod]
        public void DecryptAllocating_ThrowsShieldChainStepException_When_TagIsInvalid()
        {
            byte[] key = GenerateKey();
            byte[] nonce = GenerateNonce();
            byte[] plaintext = GenerateData(128);
            byte[] ad = GenerateData(32);
            (byte[] ciphertext, byte[] originalTag) = AesGcmService.EncryptAllocating(key, nonce, plaintext, ad);
            byte[] corruptedTag = CorruptBytes(originalTag);
            ProtocolChainStepException ex = Assert.ThrowsException<ProtocolChainStepException>(() =>
                AesGcmService.DecryptAllocating(key, nonce, ciphertext, corruptedTag, ad));
            Assert.IsNotNull(ex.InnerException);
            Assert.IsInstanceOfType(ex.InnerException, typeof(AuthenticationTagMismatchException));
            StringAssert.Contains(ex.Message, "authentication tag mismatch", StringComparison.OrdinalIgnoreCase);
        }
    }
}