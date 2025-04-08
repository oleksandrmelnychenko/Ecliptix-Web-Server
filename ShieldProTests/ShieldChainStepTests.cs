using Xunit.Abstractions;
using Sodium; // For SodiumCore, SodiumInterop, ScalarMult etc.
using Ecliptix.Core.Protocol; // Namespace for ShieldChainStep, ShieldMessageKey, etc.
using Ecliptix.Core.Protocol.Utilities; // Assuming Constants is here

namespace ShieldProTests;
// Or your test project namespace

public class ShieldChainStepTests : IDisposable
{
    private readonly ITestOutputHelper _output;

    // Static initialization ensures SodiumCore.Init() is called once for the test run
    static ShieldChainStepTests()
    {
        try
        {
            Sodium.SodiumCore.Init();
        }
        catch (Exception ex)
        {
            // Log somewhere critical or rethrow if init fails globally
            Console.WriteLine($"FATAL Sodium Init in static constructor: {ex.Message}");
            throw;
        }
    }

    public ShieldChainStepTests(ITestOutputHelper output)
    {
        _output = output;
        // SodiumCore.Init() moved to static constructor to avoid repeated calls
    }

    // Helper to create a default chain step for testing
    private ShieldChainStep CreateTestStep(ChainStepType stepType, uint cacheWindow = 1000)
    {
        // Generate a unique initial key for each step instance in tests
        byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        var step = new ShieldChainStep(stepType, initialKey, cacheWindow);
        SodiumInterop.SecureWipe(initialKey); // Wipe the temp key
        return step;
    }

    // Helper to create two steps, optionally starting with the same chain key
    private (ShieldChainStep sender, ShieldChainStep receiver) CreatePairedSteps(bool sameInitialChainKey = true,
        uint cacheWindow = 1000)
    {
        byte[] initialKey = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
        byte[] initialKeyReceiver =
            sameInitialChainKey ? initialKey : SodiumCore.GetRandomBytes(Constants.X25519KeySize);

        var sender = new ShieldChainStep(ChainStepType.Sender, initialKey, cacheWindow);
        var receiver = new ShieldChainStep(ChainStepType.Receiver, initialKeyReceiver, cacheWindow);

        SodiumInterop.SecureWipe(initialKey);
        if (!sameInitialChainKey) SodiumInterop.SecureWipe(initialKeyReceiver);

        return (sender, receiver);
    }

    // Helper to compare the keys stored securely in ShieldMessageKey instances
    // Returns true if keys match, false otherwise (including nulls, different lengths)
    private bool CompareMessageKeys(ShieldMessageKey? keyA, ShieldMessageKey? keyB)
    {
        if (keyA == null || keyB == null) return false;
        if (keyA.Index != keyB.Index) return false; // Basic check

        // Use stackalloc for temporary read buffers
        Span<byte> bytesA = stackalloc byte[ShieldMessageKey.KeySize];
        Span<byte> bytesB = stackalloc byte[ShieldMessageKey.KeySize];
        bool equal = false;

        try
        {
            // Assume ReadKeyMaterial handles ObjectDisposedException internally if needed
            keyA.ReadKeyMaterial(bytesA);
            keyB.ReadKeyMaterial(bytesB);
            equal = bytesA.SequenceEqual(bytesB);
        }
        catch (ObjectDisposedException odex)
        {
            _output.WriteLine($"[CompareMessageKeys] Error: Attempted to read disposed key. {odex.Message}");
            return false; // Keys can't be compared if one is disposed
        }
        catch (Exception ex)
        {
            _output.WriteLine($"[CompareMessageKeys] Unexpected error reading keys: {ex.Message}");
            return false; // General error during comparison
        }
        finally
        {
            // Clear stack buffers explicitly
            bytesA.Clear();
            bytesB.Clear();
        }

        return equal;
    }

    [Fact]
    public void Test_Initialization()
    {
        _output.WriteLine("[Test: Initialization] Running...");
        using var step = CreateTestStep(ChainStepType.Sender);

        Assert.Equal(0u, step.CurrentIndex);
        Assert.Equal(1u, step.NextMessageIndex);
        Assert.NotNull(step.PublicKeyBytes);
        Assert.Equal(Constants.X25519KeySize, step.PublicKeyBytes.Length);
        Assert.False(step.PublicKeyBytes.All(b => b == 0), "Public key should not be all zeros.");
        _output.WriteLine("[Test: Initialization] SUCCESS.");
    }

    [Fact]
    public void Test_AdvanceSenderKey_Single()
    {
        _output.WriteLine("[Test: AdvanceSenderKey_Single] Running...");
        using var step = CreateTestStep(ChainStepType.Sender);
        uint initialIndex = step.CurrentIndex;
        byte[] initialPubKey = step.PublicKeyBytes; // DH pub key shouldn't change on symmetric step

        ShieldMessageKey? key1 = null;
        try
        {
            key1 = step.AdvanceSenderKey(); // Derive key for index 1

            Assert.NotNull(key1);
            Assert.Equal(initialIndex + 1, key1.Index);
            Assert.Equal(initialIndex + 1, step.CurrentIndex);
            Assert.Equal(initialIndex + 2, step.NextMessageIndex);
            Assert.Equal(initialPubKey, step.PublicKeyBytes); // DH key should be stable

            // Verify key content isn't zero (basic check)
            Span<byte> keyBytes = stackalloc byte[ShieldMessageKey.KeySize];
            key1.ReadKeyMaterial(keyBytes);
            Assert.False(keyBytes.SequenceEqual(new byte[ShieldMessageKey.KeySize]), "Derived key is all zeros.");
            keyBytes.Clear();

            _output.WriteLine(
                $"[Test: AdvanceSenderKey_Single] Derived key for index {key1.Index}. Current index: {step.CurrentIndex}");
            _output.WriteLine("[Test: AdvanceSenderKey_Single] SUCCESS.");
        }
        finally
        {
            // ShieldMessageKey is disposable, but AdvanceSenderKey returns a reference
            // to an object now owned by the step's internal cache. We should NOT dispose it here.
            // The step's Dispose method will handle it.
        }
    }

    [Fact]
    public void Test_AdvanceSenderKey_Multiple()
    {
        _output.WriteLine("[Test: AdvanceSenderKey_Multiple] Running...");
        using var step = CreateTestStep(ChainStepType.Sender);

        ShieldMessageKey? key1 = null;
        ShieldMessageKey? key2 = null;
        Span<byte> key1Bytes = stackalloc byte[ShieldMessageKey.KeySize];
        Span<byte> key2Bytes = stackalloc byte[ShieldMessageKey.KeySize];

        try
        {
            key1 = step.AdvanceSenderKey(); // Index 1
            key2 = step.AdvanceSenderKey(); // Index 2

            Assert.NotNull(key1);
            Assert.NotNull(key2);
            Assert.Equal(1u, key1.Index);
            Assert.Equal(2u, key2.Index);
            Assert.Equal(2u, step.CurrentIndex);
            Assert.Equal(3u, step.NextMessageIndex);

            key1.ReadKeyMaterial(key1Bytes);
            key2.ReadKeyMaterial(key2Bytes);

            Assert.False(key1Bytes.SequenceEqual(key2Bytes), "Keys for different indices should not match.");

            _output.WriteLine(
                $"[Test: AdvanceSenderKey_Multiple] Derived keys for indices {key1.Index}, {key2.Index}. Current index: {step.CurrentIndex}");
            _output.WriteLine("[Test: AdvanceSenderKey_Multiple] SUCCESS.");
        }
        finally
        {
            // Keys are owned by the cache, do not dispose here.
            key1Bytes.Clear();
            key2Bytes.Clear();
        }
    }

    [Fact]
    public void Test_GetOrDeriveKeyFor_Receiver_InOrder()
    {
        _output.WriteLine("[Test: GetOrDeriveKeyFor_Receiver_InOrder] Running...");
        // Start sender and receiver with the same initial key state for this test
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true);
        using (sender)
        using (receiver) // Ensure disposal
        {
            ShieldMessageKey? keyS1 = null;
            ShieldMessageKey? keyR1 = null;
            ShieldMessageKey? keyS2 = null;
            ShieldMessageKey? keyR2 = null;
            try
            {
                // Step 1
                _output.WriteLine("[Receiver_InOrder] Deriving key 1...");
                keyS1 = sender.AdvanceSenderKey();
                keyR1 = receiver.GetOrDeriveKeyFor(1);
                Assert.True(CompareMessageKeys(keyS1, keyR1), "Keys for index 1 do not match.");
                Assert.Equal(1u, sender.CurrentIndex);
                Assert.Equal(1u, receiver.CurrentIndex);

                // Step 2
                _output.WriteLine("[Receiver_InOrder] Deriving key 2...");
                keyS2 = sender.AdvanceSenderKey();
                keyR2 = receiver.GetOrDeriveKeyFor(2);
                Assert.True(CompareMessageKeys(keyS2, keyR2), "Keys for index 2 do not match.");
                Assert.Equal(2u, sender.CurrentIndex);
                Assert.Equal(2u, receiver.CurrentIndex);

                _output.WriteLine("[Test: GetOrDeriveKeyFor_Receiver_InOrder] SUCCESS.");
            }
            finally
            {
                // Keys owned by cache
            }
        }
    }

    [Fact]
    public void Test_GetOrDeriveKeyFor_Receiver_OutOfOrder()
    {
        _output.WriteLine("[Test: GetOrDeriveKeyFor_Receiver_OutOfOrder] Running...");
        var (sender, receiver) =
            CreatePairedSteps(sameInitialChainKey: true, cacheWindow: 5); // Ensure cache window > 3
        using (sender)
        using (receiver)
        {
            ShieldMessageKey? keyS1 = null, keyS2 = null, keyS3 = null;
            ShieldMessageKey? keyR1 = null, keyR2 = null, keyR3 = null;
            try
            {
                // Sender generates 1, 2, 3
                _output.WriteLine("[Receiver_OutOfOrder] Sender deriving keys 1, 2, 3...");
                keyS1 = sender.AdvanceSenderKey();
                keyS2 = sender.AdvanceSenderKey();
                keyS3 = sender.AdvanceSenderKey();
                Assert.Equal(3u, sender.CurrentIndex);

                // Receiver gets 3 first
                _output.WriteLine("[Receiver_OutOfOrder] Receiver getting key 3 (skip)...");
                keyR3 = receiver.GetOrDeriveKeyFor(3);
                Assert.Equal(3u, receiver.CurrentIndex);
                Assert.True(CompareMessageKeys(keyS3, keyR3), "Keys for index 3 (received first) do not match.");

                // Receiver gets 2 (cached)
                _output.WriteLine("[Receiver_OutOfOrder] Receiver getting key 2 (cached)...");
                keyR2 = receiver.GetOrDeriveKeyFor(2); // Should come from cache now
                Assert.Equal(3u, receiver.CurrentIndex); // Index shouldn't change getting old key
                Assert.True(CompareMessageKeys(keyS2, keyR2), "Keys for index 2 (received second) do not match.");

                // Receiver gets 1 (cached)
                _output.WriteLine("[Receiver_OutOfOrder] Receiver getting key 1 (cached)...");
                keyR1 = receiver.GetOrDeriveKeyFor(1); // Should come from cache
                Assert.Equal(3u, receiver.CurrentIndex);
                Assert.True(CompareMessageKeys(keyS1, keyR1), "Keys for index 1 (received third) do not match.");

                _output.WriteLine("[Test: GetOrDeriveKeyFor_Receiver_OutOfOrder] SUCCESS.");
            }
            finally
            {
                // Keys owned by cache
            }
        }
    }

    [Fact]
    public void Test_GetOrDeriveKeyFor_IndexTooOld_And_NotCached() // Renamed test slightly
    {
        _output.WriteLine("[Test: GetOrDeriveKeyFor_IndexTooOld_And_NotCached] Running...");
        using var receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow: 5);
        ShieldMessageKey? keyR1_derived = null;
        ShieldMessageKey? keyR1_cached = null;
        uint expectedCurrentIndex = 2; // Define expected state

        try
        {
            _output.WriteLine("[IndexTooOld] Deriving keys 1, 2...");
            keyR1_derived = receiver.GetOrDeriveKeyFor(1);
            receiver.GetOrDeriveKeyFor(2);
            Assert.Equal(expectedCurrentIndex, receiver.CurrentIndex);

            // --- Test Case: Index <= CurrentIndex BUT present in cache ---
            _output.WriteLine("[IndexTooOld] Attempting to get key 1 (should be cached)...");
            keyR1_cached = receiver.GetOrDeriveKeyFor(1); // Should SUCCEED
            Assert.NotNull(keyR1_cached);
            Assert.Same(keyR1_derived, keyR1_cached);
            Assert.Equal(expectedCurrentIndex, receiver.CurrentIndex); // Index unchanged

            // --- Test Case: Index <= CurrentIndex AND NOT derivable/cached ---
            _output.WriteLine("[IndexTooOld] Attempting to get key 0 (too old and not cached)...");
            uint targetOldIndex = 0;
            var ex0 = Assert.Throws<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(targetOldIndex));

            // Assert the core components of the message instead of the exact substring
            Assert.Contains($"index {targetOldIndex}", ex0.Message); // Check the failing index is mentioned
            Assert.Contains("too old", ex0.Message); // Check the reason is mentioned
            Assert.Contains($"current index: {expectedCurrentIndex}", ex0.Message); // Check the context is correct

            _output.WriteLine($"[IndexTooOld] Verified exception message for index 0: {ex0.Message}");
            _output.WriteLine("[Test: GetOrDeriveKeyFor_IndexTooOld_And_NotCached] SUCCESS.");
        }
        finally
        {
            // Keys disposed by using statement for receiver
        }
    }

    [Fact]
    public void Test_CachePruningEffect()
    {
        _output.WriteLine("[Test: CachePruningEffect] Running...");
        uint cacheWindow = 2;
        // Need to derive CurrentIndex + 1 keys to potentially prune oldest ones
        // To prune keys < (CurrentIndex - CacheWindow), we need CurrentIndex to advance.
        // If CurrentIndex = 5, minIndex = 5 - 2 = 3. Keys 1, 2 should be pruned.
        uint keysToDerive = cacheWindow + 3; // Derive up to index 5

        using var receiver = CreateTestStep(ChainStepType.Receiver, cacheWindow);
        try
        {
            _output.WriteLine($"[CachePruningEffect] Deriving {keysToDerive} keys with cache window {cacheWindow}...");
            for (uint i = 1; i <= keysToDerive; i++)
            {
                receiver.GetOrDeriveKeyFor(i);
            }

            Assert.Equal(keysToDerive, receiver.CurrentIndex); // Current index is 5

            // Key 3 should be available (within window: 5 - 2 = 3)
            _output.WriteLine("[CachePruningEffect] Getting key 3 (should be cached)...");
            Assert.NotNull(receiver.GetOrDeriveKeyFor(3));

            // Key 2 should have been pruned ( index 2 < minIndex 3 )
            _output.WriteLine("[CachePruningEffect] Attempting to get key 2 (should be pruned)...");
            var ex2 = Assert.Throws<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(2));
            Assert.Contains("index 2 is too old", ex2.Message);

            // Key 1 should have been pruned ( index 1 < minIndex 3 )
            _output.WriteLine("[CachePruningEffect] Attempting to get key 1 (should be pruned)...");
            var ex1 = Assert.Throws<ShieldChainStepException>(() => receiver.GetOrDeriveKeyFor(1));
            Assert.Contains("index 1 is too old", ex1.Message);

            _output.WriteLine("[Test: CachePruningEffect] SUCCESS.");
        }
        finally
        {
            /* Receiver disposed by using */
        }
    }


    [Fact]
    public void Test_RotateDhChain_StateReset_Verified() // Renamed
    {
        _output.WriteLine("[Test: RotateDhChain_StateReset_Verified] Running...");
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: false);
        using (sender)
        using (receiver)
        {
            ShieldMessageKey? keyS1 = null;
            ShieldMessageKey? keyR1 = null;
            try
            {
                // Arrange: Derive some initial keys to set state > 0
                keyS1 = sender.AdvanceSenderKey(); // Sender Index 1
                keyR1 = receiver.GetOrDeriveKeyFor(1); // Receiver Index 1
                Assert.Equal(1u, sender.CurrentIndex);
                byte[] initialSenderPubKey = sender.PublicKeyBytes;
                uint initialSenderIndex = sender.CurrentIndex;

                // Act: Perform DH rotation
                _output.WriteLine("[RotateDhChain_StateReset_Verified] Performing DH rotation for sender...");
                sender.RotateDhChain(receiver.PublicKeyBytes);

                // Assert: Check state reset
                _output.WriteLine("[RotateDhChain_StateReset_Verified] Verifying sender state reset...");
                Assert.Equal(0u, sender.CurrentIndex); // Index must reset to 0
                Assert.NotEqual(initialSenderIndex, sender.CurrentIndex); // Verify index actually changed from 1
                Assert.NotEqual(initialSenderPubKey, sender.PublicKeyBytes); // DH public key must change

                // Assert: Verify deriving the *next* key (index 1 post-reset) works
                _output.WriteLine("[RotateDhChain_StateReset_Verified] Verifying derivation of new key 1 works...");
                ShieldMessageKey? keyS1_post = null;
                keyS1_post = sender.GetOrDeriveKeyFor(1); // Should succeed, deriving NEW key 1
                Assert.NotNull(keyS1_post);
                Assert.Equal(1u, keyS1_post.Index);
                Assert.Equal(1u, sender.CurrentIndex); // Sender index advances to 1 again

                _output.WriteLine("[Test: RotateDhChain_StateReset_Verified] SUCCESS.");
            }
            finally
            {
                // Message keys owned by cache, disposed via using
            }
        }
    }

    [Fact]
    public void Test_RotateDhChain_MatchingKeysAfterRotation()
    {
        _output.WriteLine("[Test: RotateDhChain_MatchingKeys] Running...");
        var (sender, receiver) = CreatePairedSteps(sameInitialChainKey: true); // Start aligned
        using (sender)
        using (receiver)
        {
            ShieldMessageKey? keyS_pre = null, keyR_pre = null;
            ShieldMessageKey? keyS_post = null, keyR_post = null;
            try
            {
                // Optional: derive pre-rotation keys
                keyS_pre = sender.AdvanceSenderKey();
                keyR_pre = receiver.GetOrDeriveKeyFor(1);
                Assert.True(CompareMessageKeys(keyS_pre, keyR_pre), "Pre-rotation keys didn't match");

                // Store public keys before rotation
                byte[] senderPubKeyPre = sender.PublicKeyBytes;
                byte[] receiverPubKeyPre = receiver.PublicKeyBytes;

                // Perform corresponding rotations
                // Sender rotates using Receiver's Pre-rotation public key
                // Receiver rotates using Sender's Pre-rotation public key
                _output.WriteLine("[RotateDhChain_MatchingKeys] Performing DH rotations...");
                sender.RotateDhChain(receiverPubKeyPre);
                receiver.RotateDhChain(senderPubKeyPre);

                // Verify state reset (optional, covered by other test)
                Assert.Equal(0u, sender.CurrentIndex);
                Assert.Equal(0u, receiver.CurrentIndex);
                Assert.NotEqual(senderPubKeyPre, sender.PublicKeyBytes);
                Assert.NotEqual(receiverPubKeyPre, receiver.PublicKeyBytes);

                // Derive keys *after* rotation
                _output.WriteLine("[RotateDhChain_MatchingKeys] Deriving keys post-rotation...");
                keyS_post = sender.AdvanceSenderKey(); // Index 1 (post-rotation)
                keyR_post = receiver.GetOrDeriveKeyFor(1); // Index 1 (post-rotation)

                // Assert post-rotation keys match
                Assert.NotNull(keyS_post);
                Assert.NotNull(keyR_post);
                Assert.Equal(1u, keyS_post.Index);
                Assert.Equal(1u, keyR_post.Index);
                Assert.True(CompareMessageKeys(keyS_post, keyR_post), "Post-rotation keys do NOT match.");

                _output.WriteLine("[Test: RotateDhChain_MatchingKeys] SUCCESS.");
            }
            finally
            {
                /* Keys owned by cache */
            }
        }
    }

    [Fact]
    public void Test_UseAfterDispose()
    {
        _output.WriteLine("[Test: UseAfterDispose] Running...");
        var step = CreateTestStep(ChainStepType.Sender);
        byte[] pkBytes = step.PublicKeyBytes; // Get PK before disposing
        step.Dispose(); // Explicitly dispose

        _output.WriteLine("[UseAfterDispose] Attempting operations after dispose...");
        Assert.Throws<ObjectDisposedException>(() => step.CurrentIndex); // Accessing property
        Assert.Throws<ObjectDisposedException>(() => step.AdvanceSenderKey());
        Assert.Throws<ObjectDisposedException>(() => step.GetOrDeriveKeyFor(1));
        Assert.Throws<ObjectDisposedException>(() => step.RotateDhChain(pkBytes));

        _output.WriteLine("[Test: UseAfterDispose] SUCCESS.");
    }

    // Dispose method for the test class itself (if needed)
    public void Dispose()
    {
        // Cleanup shared resources if any were set up for the whole class
    }
}