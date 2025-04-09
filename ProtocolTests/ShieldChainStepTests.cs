using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace ProtocolTests;

[TestClass]
public class ShieldChainStepTests
{
    private TestContext testContextInstance;
    public TestContext TestContext { get => testContextInstance; set => testContextInstance = value; }

    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        try
        {
            SodiumCore.Init();
            context.WriteLine("Sodium Initialized for ShieldChainStepTests.");
        }
        catch (Exception ex)
        {
            context.WriteLine($"FATAL Sodium Init: {ex.Message}");
            throw;
        }
    }

    private static ShieldChainStep CreateTestStep(ChainStepType stepType, uint cacheWindow = 1000)
    {
        byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        var step = new ShieldChainStep(stepType, initialKey, cacheWindow);
        SodiumInterop.SecureWipe(initialKey);
        return step;
    }

    private static (ShieldChainStep sender, ShieldChainStep receiver) CreatePairedSteps(bool sameInitialChainKey = true, uint cacheWindow = 1000)
    {
        byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        byte[] initialKeyReceiver = sameInitialChainKey ? initialKey : SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        var sender = new ShieldChainStep(ChainStepType.Sender, initialKey, cacheWindow);
        var receiver = new ShieldChainStep(ChainStepType.Receiver, initialKeyReceiver, cacheWindow);
        SodiumInterop.SecureWipe(initialKey);
        if (!sameInitialChainKey) SodiumInterop.SecureWipe(initialKeyReceiver);
        return (sender, receiver);
    }

    private bool CompareMessageKeys(ShieldMessageKey? keyA, ShieldMessageKey? keyB)
    {
        if (keyA == null || keyB == null) return false;
        if (keyA.Index != keyB.Index) return false;
        Span<byte> bytesA = stackalloc byte[ShieldMessageKey.KeySize];
        Span<byte> bytesB = stackalloc byte[ShieldMessageKey.KeySize];
        bool equal = false;
        try
        {
            keyA.ReadKeyMaterial(bytesA);
            keyB.ReadKeyMaterial(bytesB);
            equal = bytesA.SequenceEqual(bytesB);
        }
        catch (ObjectDisposedException odex)
        {
            Console.WriteLine($"[CompareMessageKeys] Error: Read disposed key. {odex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CompareMessageKeys] Unexpected error reading keys: {ex.Message}");
            return false;
        }
        finally
        {
            bytesA.Clear();
            bytesB.Clear();
        }
        return equal;
    }

    [TestMethod]
    public void Test_Initialization()
    {
        using var step = CreateTestStep(ChainStepType.Sender);
        Assert.AreEqual(0u, step.CurrentIndex);
        Assert.AreEqual(1u, step.NextMessageIndex);
        Assert.IsNotNull(step.PublicKeyBytes);
        Assert.AreEqual(Constants.X25519KeySize, step.PublicKeyBytes.Length);
        Assert.IsFalse(step.PublicKeyBytes.All(b => b == 0));
    }

    [TestMethod]
    public void Test_AdvanceSenderKey_Single()
    {
        using var step = CreateTestStep(ChainStepType.Sender);
        uint initialIndex = step.CurrentIndex;
        byte[] initialPubKey = step.PublicKeyBytes;
        byte[] peerPubKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize); // Dummy peer key
        (ShieldMessageKey key1, byte[]? newDhKey) = step.AdvanceSenderKey(peerPubKey);
        SodiumInterop.SecureWipe(peerPubKey);

        Assert.IsNotNull(key1);
        Assert.AreEqual(initialIndex + 1, key1.Index);
        Assert.AreEqual(initialIndex + 1, step.CurrentIndex);
        Assert.AreEqual(initialIndex + 2, step.NextMessageIndex);
        CollectionAssert.AreEqual(initialPubKey, step.PublicKeyBytes); // No rotation yet
        Assert.IsNull(newDhKey); // No DH rotation for first message
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
        byte[] peerPubKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize); // Dummy peer key
        try
        {
            (ShieldMessageKey key1, _) = step.AdvanceSenderKey(peerPubKey);
            (ShieldMessageKey key2, _) = step.AdvanceSenderKey(peerPubKey);
            Assert.IsNotNull(key1); Assert.IsNotNull(key2);
            Assert.AreEqual(1u, key1.Index); Assert.AreEqual(2u, key2.Index);
            Assert.AreEqual(2u, step.CurrentIndex); Assert.AreEqual(3u, step.NextMessageIndex);
            key1.ReadKeyMaterial(key1Bytes); key2.ReadKeyMaterial(key2Bytes);
            CollectionAssert.AreNotEqual(key1Bytes.ToArray(), key2Bytes.ToArray());
        }
        finally
        {
            SodiumInterop.SecureWipe(peerPubKey);
            key1Bytes.Clear();
            key2Bytes.Clear();
        }
    }

    [TestMethod]
    public void Test_GetOrDeriveKeyFor_Receiver_InOrder()
    {
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true);
        using (sender) using (receiver)
        {
            byte[] receiverPubKey = receiver.PublicKeyBytes;
            (ShieldMessageKey keyS1, _) = sender.AdvanceSenderKey(receiverPubKey);
            ShieldMessageKey keyR1 = receiver.GetOrDeriveKeyFor(1);
            Assert.IsTrue(CompareMessageKeys(keyS1, keyR1));
            Assert.AreEqual(1u, sender.CurrentIndex);
            Assert.AreEqual(1u, receiver.CurrentIndex);

            (ShieldMessageKey keyS2, _) = sender.AdvanceSenderKey(receiverPubKey);
            ShieldMessageKey keyR2 = receiver.GetOrDeriveKeyFor(2);
            Assert.IsTrue(CompareMessageKeys(keyS2, keyR2));
            Assert.AreEqual(2u, sender.CurrentIndex);
            Assert.AreEqual(2u, receiver.CurrentIndex);
        }
    }

    [TestMethod]
    public void Test_GetOrDeriveKeyFor_Receiver_OutOfOrder()
    {
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true, cacheWindow: 5);
        using (sender) using (receiver)
        {
            byte[] receiverPubKey = receiver.PublicKeyBytes;
            (ShieldMessageKey keyS1, _) = sender.AdvanceSenderKey(receiverPubKey);
            (ShieldMessageKey keyS2, _) = sender.AdvanceSenderKey(receiverPubKey);
            (ShieldMessageKey keyS3, _) = sender.AdvanceSenderKey(receiverPubKey);
            Assert.AreEqual(3u, sender.CurrentIndex);

            ShieldMessageKey keyR3 = receiver.GetOrDeriveKeyFor(3);
            Assert.AreEqual(3u, receiver.CurrentIndex);
            Assert.IsTrue(CompareMessageKeys(keyS3, keyR3));

            ShieldMessageKey keyR2 = receiver.GetOrDeriveKeyFor(2);
            Assert.AreEqual(3u, receiver.CurrentIndex);
            Assert.IsTrue(CompareMessageKeys(keyS2, keyR2));

            ShieldMessageKey keyR1 = receiver.GetOrDeriveKeyFor(1);
            Assert.AreEqual(3u, receiver.CurrentIndex);
            Assert.IsTrue(CompareMessageKeys(keyS1, keyR1));
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
        Assert.AreSame(keyR1Derived, keyR1Cached);
        Assert.AreEqual(expectedCurrentIndex, receiver.CurrentIndex);

        uint targetOldIndex = 0;
        var ex0 = Assert.ThrowsException<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(targetOldIndex));
        StringAssert.Contains(ex0.Message, $"index {targetOldIndex}");
        StringAssert.Contains(ex0.Message, "too old");
        StringAssert.Contains(ex0.Message, $"current index: {expectedCurrentIndex}");
    }

    [TestMethod]
    public void Test_CachePruningEffect()
    {
        const uint cacheWindow = 2;
        const uint keysToDerive = cacheWindow + 3; // Derive 5 keys
        using var receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow);
        for (uint i = 1; i <= keysToDerive; i++)
        {
            receiver.GetOrDeriveKeyFor(i);
        }
        Assert.AreEqual(keysToDerive, receiver.CurrentIndex);

        Assert.IsNotNull(receiver.GetOrDeriveKeyFor(3)); // Within cache window (5 - 2 = 3)
        var ex2 = Assert.ThrowsException<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(2));
        StringAssert.Contains(ex2.Message, "index 2 is too old");
        var ex1 = Assert.ThrowsException<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(1));
        StringAssert.Contains(ex1.Message, "index 1 is too old");
    }

    [TestMethod]
    public void Test_RotateDhChain_StateReset_Verified()
    {
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: false);
        using (sender) using (receiver)
        {
            byte[] receiverPubKey = receiver.PublicKeyBytes;
            (var keyS1, _) = sender.AdvanceSenderKey(receiverPubKey);
            receiver.GetOrDeriveKeyFor(1);
            Assert.AreEqual(1u, sender.CurrentIndex);

            byte[] initialSenderPubKey = sender.PublicKeyBytes;
            uint initialSenderIndex = sender.CurrentIndex;
            sender.RotateDhChain(receiver.PublicKeyBytes);
            Assert.AreEqual(0u, sender.CurrentIndex);
            Assert.AreNotEqual(initialSenderIndex, sender.CurrentIndex);
            CollectionAssert.AreNotEqual(initialSenderPubKey, sender.PublicKeyBytes);

            (var keyS1Post, _) = sender.AdvanceSenderKey(receiver.PublicKeyBytes);
            Assert.IsNotNull(keyS1Post);
            Assert.AreEqual(1u, keyS1Post.Index);
            Assert.AreEqual(1u, sender.CurrentIndex);
        }
    }

    [TestMethod]
    public void Test_RotateDhChain_MatchingKeysAfterRotation()
    {
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true);
        using (sender) using (receiver)
        {
            byte[] receiverPubKeyPre = receiver.PublicKeyBytes;
            byte[] senderPubKeyPre = sender.PublicKeyBytes;

            (ShieldMessageKey keySPre, _) = sender.AdvanceSenderKey(receiverPubKeyPre);
            ShieldMessageKey keyRPre = receiver.GetOrDeriveKeyFor(1);
            Assert.IsTrue(CompareMessageKeys(keySPre, keyRPre));

            sender.RotateDhChain(receiverPubKeyPre);
            receiver.RotateDhChain(senderPubKeyPre);

            Assert.AreEqual(0u, sender.CurrentIndex);
            Assert.AreEqual(0u, receiver.CurrentIndex);
            CollectionAssert.AreNotEqual(senderPubKeyPre, sender.PublicKeyBytes);
            CollectionAssert.AreNotEqual(receiverPubKeyPre, receiver.PublicKeyBytes);

            byte[] newReceiverPubKey = receiver.PublicKeyBytes;
            (ShieldMessageKey keySPost, _) = sender.AdvanceSenderKey(newReceiverPubKey);
            ShieldMessageKey keyRPost = receiver.GetOrDeriveKeyFor(1);

            Assert.IsNotNull(keySPost);
            Assert.IsNotNull(keyRPost);
            Assert.AreEqual(1u, keySPost.Index);
            Assert.AreEqual(1u, keyRPost.Index);
            Assert.IsTrue(CompareMessageKeys(keySPost, keyRPost));
        }
    }

    [TestMethod]
    public void Test_AdvanceSenderKey_DHRotation_Every1000()
    {
        using var sender = CreateTestStep(ChainStepType.Sender, cacheWindow: 1500); // Larger cache to test rotation
        byte[] peerPubKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        byte[] initialPubKey = sender.PublicKeyBytes;

        try
        {
            // Advance to 999 - no rotation
            for (uint i = 1; i <= 999; i++)
            {
                (var key, var newDhKey) = sender.AdvanceSenderKey(peerPubKey);
                Assert.AreEqual(i, key.Index);
                Assert.IsNull(newDhKey);
                CollectionAssert.AreEqual(initialPubKey, sender.PublicKeyBytes);
            }
            Assert.AreEqual(999u, sender.CurrentIndex);

            // 1000th message - expect rotation
            (var key1000, var newDhKey1000) = sender.AdvanceSenderKey(peerPubKey);
            Assert.AreEqual(1u, key1000.Index); // Index resets to 1 after rotation
            Assert.IsNotNull(newDhKey1000);
            Assert.AreEqual(1u, sender.CurrentIndex);
            CollectionAssert.AreNotEqual(initialPubKey, sender.PublicKeyBytes);
            CollectionAssert.AreEqual(newDhKey1000, sender.PublicKeyBytes);

            // Advance to 1999 - no further rotation
            byte[] postRotationPubKey = sender.PublicKeyBytes;
            for (uint i = 2; i <= 999; i++)
            {
                (var key, var newDhKey) = sender.AdvanceSenderKey(peerPubKey);
                Assert.AreEqual(i, key.Index);
                Assert.IsNull(newDhKey);
                CollectionAssert.AreEqual(postRotationPubKey, sender.PublicKeyBytes);
            }
            Assert.AreEqual(999u, sender.CurrentIndex);

            // 2000th message (1000 post-rotation) - expect rotation again
            (var key2000, var newDhKey2000) = sender.AdvanceSenderKey(peerPubKey);
            Assert.AreEqual(1u, key2000.Index);
            Assert.IsNotNull(newDhKey2000);
            Assert.AreEqual(1u, sender.CurrentIndex);
            CollectionAssert.AreNotEqual(postRotationPubKey, sender.PublicKeyBytes);
            CollectionAssert.AreEqual(newDhKey2000, sender.PublicKeyBytes);
        }
        finally
        {
            SodiumInterop.SecureWipe(peerPubKey);
        }
    }

    [TestMethod]
    public void Test_UseAfterDispose()
    {
        var step = CreateTestStep(ChainStepType.Sender);
        byte[] pkBytes = step.PublicKeyBytes;
        step.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() => { var _ = step.CurrentIndex; });
        Assert.ThrowsException<ObjectDisposedException>(() => { var _ = step.NextMessageIndex; });
        Assert.ThrowsException<ObjectDisposedException>(() => step.AdvanceSenderKey(pkBytes));
        Assert.ThrowsException<ObjectDisposedException>(() => step.GetOrDeriveKeyFor(1));
        Assert.ThrowsException<ObjectDisposedException>(() => step.RotateDhChain(pkBytes));
    }
}