using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Sodium;
// MSTest namespace
// For SodiumCore, SodiumInterop
// Main namespace

// For Constants, Exceptions

namespace ProtocolTests // Your test project namespace
{
    [TestClass] // Use MSTest attribute
    public class ShieldChainStepTests // No IDisposable needed here usually
    {
        // Optional: TestContext for output
        // private TestContext testContextInstance;
        // public TestContext TestContext { get => testContextInstance; set => testContextInstance = value; }

        // --- ClassInitialize for SodiumCore.Init (runs once) ---
        [ClassInitialize]
        public static void ClassInit(TestContext context) // Needs TestContext parameter
        {
            try
            {
                Sodium.SodiumCore.Init();
                context.WriteLine("Sodium Initialized for ShieldChainStepTests."); // Use context for output
            }
            catch (Exception ex)
            {
                context.WriteLine($"FATAL Sodium Init: {ex.Message}");
                throw;
            }
        }

        // --- Helper Methods ---

        private static ShieldChainStep CreateTestStep(ChainStepType stepType, uint cacheWindow = 1000)
        {
            byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
            var step = new ShieldChainStep(stepType, initialKey, cacheWindow);
            SodiumInterop.SecureWipe(initialKey);
            return step;
        }

        private (ShieldChainStep sender, ShieldChainStep receiver) CreatePairedSteps(bool sameInitialChainKey = true, uint cacheWindow = 1000)
        {
            byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
            byte[] initialKeyReceiver = sameInitialChainKey ? initialKey : SodiumCore.GetRandomBytes(Constants.X25519KeySize);
            var sender = new ShieldChainStep(ChainStepType.Sender, initialKey, cacheWindow);
            var receiver = new ShieldChainStep(ChainStepType.Receiver, initialKeyReceiver, cacheWindow);
            SodiumInterop.SecureWipe(initialKey);
            if (!sameInitialChainKey) SodiumInterop.SecureWipe(initialKeyReceiver);
            return (sender, receiver);
        }

        // Helper to compare ShieldMessageKey contents
        // Output via Console here as TestContext isn't easily available in static/helpers
        private bool CompareMessageKeys(ShieldMessageKey? keyA, ShieldMessageKey? keyB)
        {
             if (keyA == null || keyB == null) return false;
             if (keyA.Index != keyB.Index) return false;
             Span<byte> bytesA = stackalloc byte[ShieldMessageKey.KeySize];
             Span<byte> bytesB = stackalloc byte[ShieldMessageKey.KeySize];
             bool equal = false;
             try {
                 keyA.ReadKeyMaterial(bytesA);
                 keyB.ReadKeyMaterial(bytesB);
                 equal = bytesA.SequenceEqual(bytesB);
             }
             catch (ObjectDisposedException odex) { Console.WriteLine($"[CompareMessageKeys] Error: Read disposed key. {odex.Message}"); return false; }
             catch (Exception ex) { Console.WriteLine($"[CompareMessageKeys] Unexpected error reading keys: {ex.Message}"); return false; }
             finally { bytesA.Clear(); bytesB.Clear(); }
             return equal;
        }

        // --- Tests ---

        [TestMethod] // Use MSTest attribute
        public void Test_Initialization()
        {
            using var step = CreateTestStep(ChainStepType.Sender);
            Assert.AreEqual(0u, step.CurrentIndex); // Use AreEqual
            Assert.AreEqual(1u, step.NextMessageIndex);
            Assert.IsNotNull(step.PublicKeyBytes); // Use IsNotNull
            Assert.AreEqual(Constants.X25519KeySize, step.PublicKeyBytes.Length);
            Assert.IsFalse(step.PublicKeyBytes.All(b => b == 0)); // Use IsFalse
        }

        [TestMethod]
        public void Test_AdvanceSenderKey_Single()
        {
            using var step = CreateTestStep(ChainStepType.Sender);
            uint initialIndex = step.CurrentIndex;
            byte[] initialPubKey = step.PublicKeyBytes;
            ShieldMessageKey key1 = step.AdvanceSenderKey(); // Note: Key is owned by step's cache

            Assert.IsNotNull(key1);
            Assert.AreEqual(initialIndex + 1, key1.Index);
            Assert.AreEqual(initialIndex + 1, step.CurrentIndex);
            Assert.AreEqual(initialIndex + 2, step.NextMessageIndex);
            CollectionAssert.AreEqual(initialPubKey, step.PublicKeyBytes); // Use CollectionAssert for arrays
            Span<byte> keyBytes = stackalloc byte[ShieldMessageKey.KeySize];
            try
            {
                key1.ReadKeyMaterial(keyBytes);
                Assert.IsFalse(keyBytes.SequenceEqual(new byte[ShieldMessageKey.KeySize]));
            }
            finally
            {
                keyBytes.Clear();
            }
        }

        [TestMethod]
        public void Test_AdvanceSenderKey_Multiple()
        {
            using var step = CreateTestStep(ChainStepType.Sender);
            Span<byte> key1Bytes = stackalloc byte[ShieldMessageKey.KeySize];
            Span<byte> key2Bytes = stackalloc byte[ShieldMessageKey.KeySize];
            try
            {
                ShieldMessageKey key1 = step.AdvanceSenderKey();
                ShieldMessageKey key2 = step.AdvanceSenderKey();
                Assert.IsNotNull(key1); Assert.IsNotNull(key2);
                Assert.AreEqual(1u, key1.Index); Assert.AreEqual(2u, key2.Index);
                Assert.AreEqual(2u, step.CurrentIndex); Assert.AreEqual(3u, step.NextMessageIndex);
                key1.ReadKeyMaterial(key1Bytes); key2.ReadKeyMaterial(key2Bytes);
                // Use CollectionAssert.AreNotEqual or Assert.IsFalse with SequenceEqual
                CollectionAssert.AreNotEqual(key1Bytes.ToArray(), key2Bytes.ToArray());
                // Or: Assert.IsFalse(key1Bytes.SequenceEqual(key2Bytes));
            }
            finally { key1Bytes.Clear(); key2Bytes.Clear(); }
        }

        [TestMethod]
        public void Test_GetOrDeriveKeyFor_Receiver_InOrder()
        {
            var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true);
            using (sender) using (receiver)
            {
                ShieldMessageKey keyS1 = sender.AdvanceSenderKey(); ShieldMessageKey keyR1 = receiver.GetOrDeriveKeyFor(1);
                Assert.IsTrue(CompareMessageKeys(keyS1, keyR1)); Assert.AreEqual(1u, sender.CurrentIndex); Assert.AreEqual(1u, receiver.CurrentIndex);
                ShieldMessageKey keyS2 = sender.AdvanceSenderKey(); ShieldMessageKey keyR2 = receiver.GetOrDeriveKeyFor(2);
                Assert.IsTrue(CompareMessageKeys(keyS2, keyR2)); Assert.AreEqual(2u, sender.CurrentIndex); Assert.AreEqual(2u, receiver.CurrentIndex);
            }
        }

        [TestMethod]
        public void Test_GetOrDeriveKeyFor_Receiver_OutOfOrder()
        {
            var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true, cacheWindow: 5);
            using (sender) using (receiver)
            {
                ShieldMessageKey keyS1 = sender.AdvanceSenderKey(); ShieldMessageKey keyS2 = sender.AdvanceSenderKey(); ShieldMessageKey keyS3 = sender.AdvanceSenderKey();
                Assert.AreEqual(3u, sender.CurrentIndex);
                ShieldMessageKey keyR3 = receiver.GetOrDeriveKeyFor(3); Assert.AreEqual(3u, receiver.CurrentIndex); Assert.IsTrue(CompareMessageKeys(keyS3, keyR3));
                ShieldMessageKey keyR2 = receiver.GetOrDeriveKeyFor(2); Assert.AreEqual(3u, receiver.CurrentIndex); Assert.IsTrue(CompareMessageKeys(keyS2, keyR2));
                ShieldMessageKey keyR1 = receiver.GetOrDeriveKeyFor(1); Assert.AreEqual(3u, receiver.CurrentIndex); Assert.IsTrue(CompareMessageKeys(keyS1, keyR1));
            }
        }

        [TestMethod]
        public void Test_GetOrDeriveKeyFor_IndexTooOld_And_NotCached()
        {
            using var receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow: 5);
            const uint expectedCurrentIndex = 2;
            ShieldMessageKey keyR1Derived = receiver.GetOrDeriveKeyFor(1);
            receiver.GetOrDeriveKeyFor(2);
            Assert.AreEqual(expectedCurrentIndex, receiver.CurrentIndex);
            ShieldMessageKey keyR1Cached = receiver.GetOrDeriveKeyFor(1); // Should succeed from cache
            Assert.IsNotNull(keyR1Cached);
            Assert.AreSame(keyR1Derived, keyR1Cached); // Use AreSame to check object identity
            Assert.AreEqual(expectedCurrentIndex, receiver.CurrentIndex); // Should not change index
            uint targetOldIndex = 0;
            // Use Assert.ThrowsException
            var ex0 = Assert.ThrowsException<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(targetOldIndex));
            StringAssert.Contains(ex0.Message, $"index {targetOldIndex}"); // Use StringAssert
            StringAssert.Contains(ex0.Message, "too old");
            StringAssert.Contains(ex0.Message, $"current index: {expectedCurrentIndex}");
        }

        [TestMethod]
        public void Test_CachePruningEffect()
        {
            const uint cacheWindow = 2; const uint keysToDerive = cacheWindow + 3; // Derive 5 keys
            using var receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow);
            for (uint i = 1; i <= keysToDerive; i++) { receiver.GetOrDeriveKeyFor(i); }
            Assert.AreEqual(keysToDerive, receiver.CurrentIndex); // 5
            // Index 3 (5 - 2) should still be accessible (cached or derivable)
            Assert.IsNotNull(receiver.GetOrDeriveKeyFor(3));
            // Index 2 (< 5 - 2) should be too old and pruned
            var ex2 = Assert.ThrowsException<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(2));
            StringAssert.Contains(ex2.Message, "index 2 is too old");
            // Index 1 (< 5 - 2) should be too old and pruned
            var ex1 = Assert.ThrowsException<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(1));
            StringAssert.Contains(ex1.Message, "index 1 is too old");
        }

        [TestMethod]
        public void Test_RotateDhChain_StateReset_Verified()
        {
            var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: false);
            using (sender) using (receiver)
            {
                sender.AdvanceSenderKey(); receiver.GetOrDeriveKeyFor(1);
                Assert.AreEqual(1u, sender.CurrentIndex);
                byte[] initialSenderPubKey = sender.PublicKeyBytes;
                uint initialSenderIndex = sender.CurrentIndex;
                sender.RotateDhChain(receiver.PublicKeyBytes); // Perform rotation
                Assert.AreEqual(0u, sender.CurrentIndex); // Index reset
                Assert.AreNotEqual(initialSenderIndex, sender.CurrentIndex); // Index changed
                CollectionAssert.AreNotEqual(initialSenderPubKey, sender.PublicKeyBytes); // Public key changed
                ShieldMessageKey keyS1Post = sender.GetOrDeriveKeyFor(1); // Derive next key
                Assert.IsNotNull(keyS1Post);
                Assert.AreEqual(1u, keyS1Post.Index);
                Assert.AreEqual(1u, sender.CurrentIndex); // Index advanced again
            }
        }

        [TestMethod]
        public void Test_RotateDhChain_MatchingKeysAfterRotation()
        {
            var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true);
            using (sender) using (receiver)
            {
                 // Note: ShieldMessageKey is IDisposable, but the instance returned
                 // by AdvanceSenderKey/GetOrDeriveKeyFor is owned by the cache.
                 // We don't wrap these return values in using statements.
                ShieldMessageKey keySPre = sender.AdvanceSenderKey();
                ShieldMessageKey keyRPre = receiver.GetOrDeriveKeyFor(1);
                Assert.IsTrue(CompareMessageKeys(keySPre, keyRPre)); // Check pre-rotation keys match
                byte[] senderPubKeyPre = sender.PublicKeyBytes;
                byte[] receiverPubKeyPre = receiver.PublicKeyBytes;
                sender.RotateDhChain(receiverPubKeyPre); // Rotate sender
                receiver.RotateDhChain(senderPubKeyPre); // Rotate receiver
                Assert.AreEqual(0u, sender.CurrentIndex); Assert.AreEqual(0u, receiver.CurrentIndex); // Check indices reset
                CollectionAssert.AreNotEqual(senderPubKeyPre, sender.PublicKeyBytes); // Check keys changed
                CollectionAssert.AreNotEqual(receiverPubKeyPre, receiver.PublicKeyBytes);
                ShieldMessageKey keySPost = sender.AdvanceSenderKey(); // Derive post-rotation key
                ShieldMessageKey keyRPost = receiver.GetOrDeriveKeyFor(1); // Derive post-rotation key
                Assert.IsNotNull(keySPost); Assert.IsNotNull(keyRPost);
                Assert.AreEqual(1u, keySPost.Index); Assert.AreEqual(1u, keyRPost.Index);
                Assert.IsTrue(CompareMessageKeys(keySPost, keyRPost)); // Check post-rotation keys match
            }
        }

        [TestMethod]
        public void Test_UseAfterDispose()
        {
            var step = CreateTestStep(ChainStepType.Sender);
            byte[] pkBytes = step.PublicKeyBytes;
            step.Dispose(); // Dispose
             // Use Assert.ThrowsException
            Assert.ThrowsException<ObjectDisposedException>(() => { var _ = step.CurrentIndex; }); // Access property
            Assert.ThrowsException<ObjectDisposedException>(() => step.AdvanceSenderKey());
            Assert.ThrowsException<ObjectDisposedException>(() => step.GetOrDeriveKeyFor(1));
            Assert.ThrowsException<ObjectDisposedException>(() => step.RotateDhChain(pkBytes));
        }

        // No explicit Dispose needed for the test class itself in this case
    }
}