using Xunit.Abstractions;
using Sodium;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;

namespace ShieldProTests;

public class ShieldChainStepTests(ITestOutputHelper output) : IDisposable
{
    static ShieldChainStepTests()
    {
        try
        {
            SodiumCore.Init();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FATAL Sodium Init in static constructor: {ex.Message}");
            throw;
        }
    }

    private static ShieldChainStep CreateTestStep(ChainStepType stepType, uint cacheWindow = 1000)
    {
        byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        ShieldChainStep step = new(stepType, initialKey, cacheWindow);
        SodiumInterop.SecureWipe(initialKey);
        return step;
    }

    private (ShieldChainStep sender, ShieldChainStep receiver) CreatePairedSteps(bool sameInitialChainKey = true,
        uint cacheWindow = 1000)
    {
        byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        byte[] initialKeyReceiver =
            sameInitialChainKey ? initialKey : SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        ShieldChainStep sender = new(ChainStepType.Sender, initialKey, cacheWindow);
        ShieldChainStep receiver = new(ChainStepType.Receiver, initialKeyReceiver, cacheWindow);
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
        bool equal;
        try
        {
            keyA.ReadKeyMaterial(bytesA);
            keyB.ReadKeyMaterial(bytesB);
            equal = bytesA.SequenceEqual(bytesB);
        }
        catch (ObjectDisposedException odex)
        {
            output.WriteLine($"[CompareMessageKeys] Error: Attempted to read disposed key. {odex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            output.WriteLine($"[CompareMessageKeys] Unexpected error reading keys: {ex.Message}");
            return false;
        }
        finally
        {
            bytesA.Clear();
            bytesB.Clear();
        }

        return equal;
    }

    [Fact]
    public void Test_Initialization()
    {
        using ShieldChainStep step = CreateTestStep(ChainStepType.Sender);
        Assert.Equal(0u, step.CurrentIndex);
        Assert.Equal(1u, step.NextMessageIndex);
        Assert.NotNull(step.PublicKeyBytes);
        Assert.Equal(Constants.X25519KeySize, step.PublicKeyBytes.Length);
        Assert.False(step.PublicKeyBytes.All(b => b == 0));
    }

    [Fact]
    public void Test_AdvanceSenderKey_Single()
    {
        using ShieldChainStep step = CreateTestStep(ChainStepType.Sender);
        uint initialIndex = step.CurrentIndex;
        byte[] initialPubKey = step.PublicKeyBytes;
        ShieldMessageKey key1 = step.AdvanceSenderKey();
        Assert.NotNull(key1);
        Assert.Equal(initialIndex + 1, key1.Index);
        Assert.Equal(initialIndex + 1, step.CurrentIndex);
        Assert.Equal(initialIndex + 2, step.NextMessageIndex);
        Assert.Equal(initialPubKey, step.PublicKeyBytes);
        Span<byte> keyBytes = stackalloc byte[ShieldMessageKey.KeySize];
        key1.ReadKeyMaterial(keyBytes);
        Assert.False(keyBytes.SequenceEqual(new byte[ShieldMessageKey.KeySize]));
        keyBytes.Clear();
    }

    [Fact]
    public void Test_AdvanceSenderKey_Multiple()
    {
        using ShieldChainStep step = CreateTestStep(ChainStepType.Sender);
        Span<byte> key1Bytes = stackalloc byte[ShieldMessageKey.KeySize];
        Span<byte> key2Bytes = stackalloc byte[ShieldMessageKey.KeySize];
        try
        {
            ShieldMessageKey key1 = step.AdvanceSenderKey();
            ShieldMessageKey key2 = step.AdvanceSenderKey();
            Assert.NotNull(key1);
            Assert.NotNull(key2);
            Assert.Equal(1u, key1.Index);
            Assert.Equal(2u, key2.Index);
            Assert.Equal(2u, step.CurrentIndex);
            Assert.Equal(3u, step.NextMessageIndex);
            key1.ReadKeyMaterial(key1Bytes);
            key2.ReadKeyMaterial(key2Bytes);
            Assert.False(key1Bytes.SequenceEqual(key2Bytes));
        }
        finally
        {
            key1Bytes.Clear();
            key2Bytes.Clear();
        }
    }

    [Fact]
    public void Test_GetOrDeriveKeyFor_Receiver_InOrder()
    {
        (ShieldChainStep sender, ShieldChainStep receiver) = CreatePairedSteps(sameInitialChainKey: true);
        using (sender)
        using (receiver)
        {
            ShieldMessageKey keyS1 = sender.AdvanceSenderKey();
            ShieldMessageKey keyR1 = receiver.GetOrDeriveKeyFor(1);
            Assert.True(CompareMessageKeys(keyS1, keyR1));
            Assert.Equal(1u, sender.CurrentIndex);
            Assert.Equal(1u, receiver.CurrentIndex);
            ShieldMessageKey keyS2 = sender.AdvanceSenderKey();
            ShieldMessageKey keyR2 = receiver.GetOrDeriveKeyFor(2);
            Assert.True(CompareMessageKeys(keyS2, keyR2));
            Assert.Equal(2u, sender.CurrentIndex);
            Assert.Equal(2u, receiver.CurrentIndex);
        }
    }

    [Fact]
    public void Test_GetOrDeriveKeyFor_Receiver_OutOfOrder()
    {
        (ShieldChainStep sender, ShieldChainStep receiver) =
            CreatePairedSteps(sameInitialChainKey: true, cacheWindow: 5);
        using (sender)
        using (receiver)
        {
            ShieldMessageKey keyS1 = sender.AdvanceSenderKey();
            ShieldMessageKey keyS2 = sender.AdvanceSenderKey();
            ShieldMessageKey keyS3 = sender.AdvanceSenderKey();
            Assert.Equal(3u, sender.CurrentIndex);
            ShieldMessageKey keyR3 = receiver.GetOrDeriveKeyFor(3);
            Assert.Equal(3u, receiver.CurrentIndex);
            Assert.True(CompareMessageKeys(keyS3, keyR3));
            ShieldMessageKey keyR2 = receiver.GetOrDeriveKeyFor(2);
            Assert.Equal(3u, receiver.CurrentIndex);
            Assert.True(CompareMessageKeys(keyS2, keyR2));
            ShieldMessageKey keyR1 = receiver.GetOrDeriveKeyFor(1);
            Assert.Equal(3u, receiver.CurrentIndex);
            Assert.True(CompareMessageKeys(keyS1, keyR1));
        }
    }

    [Fact]
    public void Test_GetOrDeriveKeyFor_IndexTooOld_And_NotCached()
    {
        using ShieldChainStep receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow: 5);
        const uint expectedCurrentIndex = 2;
        ShieldMessageKey keyR1Derived = receiver.GetOrDeriveKeyFor(1);
        receiver.GetOrDeriveKeyFor(2);
        Assert.Equal(expectedCurrentIndex, receiver.CurrentIndex);
        ShieldMessageKey keyR1Cached = receiver.GetOrDeriveKeyFor(1);
        Assert.NotNull(keyR1Cached);
        Assert.Same(keyR1Derived, keyR1Cached);
        Assert.Equal(expectedCurrentIndex, receiver.CurrentIndex);
        uint targetOldIndex = 0;
        ShieldChainStepException ex0 =
            Assert.Throws<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(targetOldIndex));
        Assert.Contains($"index {targetOldIndex}", ex0.Message);
        Assert.Contains("too old", ex0.Message);
        Assert.Contains($"current index: {expectedCurrentIndex}", ex0.Message);
    }

    [Fact]
    public void Test_CachePruningEffect()
    {
        const uint cacheWindow = 2;
        const uint keysToDerive = cacheWindow + 3;
        using ShieldChainStep receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow);
        for (uint i = 1; i <= keysToDerive; i++)
        {
            receiver.GetOrDeriveKeyFor(i);
        }

        Assert.Equal(keysToDerive, receiver.CurrentIndex);
        Assert.NotNull(receiver.GetOrDeriveKeyFor(3));
        ShieldChainStepException ex2 = Assert.Throws<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(2));
        Assert.Contains("index 2 is too old", ex2.Message);
        ShieldChainStepException ex1 = Assert.Throws<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(1));
        Assert.Contains("index 1 is too old", ex1.Message);
    }

    [Fact]
    public void Test_RotateDhChain_StateReset_Verified()
    {
        (ShieldChainStep sender, ShieldChainStep receiver) = CreatePairedSteps(sameInitialChainKey: false);
        using (sender)
        using (receiver)
        {
            sender.AdvanceSenderKey();
            receiver.GetOrDeriveKeyFor(1);
            Assert.Equal(1u, sender.CurrentIndex);
            byte[] initialSenderPubKey = sender.PublicKeyBytes;
            uint initialSenderIndex = sender.CurrentIndex;
            sender.RotateDhChain(receiver.PublicKeyBytes);
            Assert.Equal(0u, sender.CurrentIndex);
            Assert.NotEqual(initialSenderIndex, sender.CurrentIndex);
            Assert.NotEqual(initialSenderPubKey, sender.PublicKeyBytes);
            ShieldMessageKey keyS1Post = sender.GetOrDeriveKeyFor(1);
            Assert.NotNull(keyS1Post);
            Assert.Equal(1u, keyS1Post.Index);
            Assert.Equal(1u, sender.CurrentIndex);
        }
    }

    [Fact]
    public void Test_RotateDhChain_MatchingKeysAfterRotation()
    {
        (ShieldChainStep sender, ShieldChainStep receiver) = CreatePairedSteps(sameInitialChainKey: true);
        using (sender)
        using (receiver)
        {
            using ShieldMessageKey keySPre = sender.AdvanceSenderKey();
            ShieldMessageKey keyRPre = receiver.GetOrDeriveKeyFor(1);
            Assert.True(CompareMessageKeys(keySPre, keyRPre));
            byte[] senderPubKeyPre = sender.PublicKeyBytes;
            byte[] receiverPubKeyPre = receiver.PublicKeyBytes;
            sender.RotateDhChain(receiverPubKeyPre);
            receiver.RotateDhChain(senderPubKeyPre);
            Assert.Equal(0u, sender.CurrentIndex);
            Assert.Equal(0u, receiver.CurrentIndex);
            Assert.NotEqual(senderPubKeyPre, sender.PublicKeyBytes);
            Assert.NotEqual(receiverPubKeyPre, receiver.PublicKeyBytes);
            ShieldMessageKey keySPost = sender.AdvanceSenderKey();
            ShieldMessageKey keyRPost = receiver.GetOrDeriveKeyFor(1);
            Assert.NotNull(keySPost);
            Assert.NotNull(keyRPost);
            Assert.Equal(1u, keySPost.Index);
            Assert.Equal(1u, keyRPost.Index);
            Assert.True(CompareMessageKeys(keySPost, keyRPost));
        }
    }

    [Fact]
    public void Test_UseAfterDispose()
    {
        ShieldChainStep step = CreateTestStep(ChainStepType.Sender);
        byte[] pkBytes = step.PublicKeyBytes;
        step.Dispose();
        Assert.Throws<ObjectDisposedException>(() => step.CurrentIndex);
        Assert.Throws<ObjectDisposedException>(() => step.AdvanceSenderKey());
        Assert.Throws<ObjectDisposedException>(() => step.GetOrDeriveKeyFor(1));
        Assert.Throws<ObjectDisposedException>(() => step.RotateDhChain(pkBytes));
    }

    public void Dispose()
    {
    }
}