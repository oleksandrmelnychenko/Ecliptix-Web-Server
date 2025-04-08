/*using Xunit.Abstractions;
using System.Diagnostics;
using System.Text;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.CipherPayload;

namespace ShieldProTests;

public class ShieldProPowerTests : IAsyncDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly LocalKeyMaterial _sharedAliceKeys;
    private readonly LocalKeyMaterial _sharedBobKeys;
    private readonly ShieldSessionManager _sharedAliceManager;
    private readonly ShieldSessionManager _sharedBobManager;
    private readonly ShieldPro _sharedAliceShieldPro;
    private readonly ShieldPro _sharedBobShieldPro;

    static ShieldProPowerTests()
    {
        try
        {
            Sodium.SodiumCore.Init();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FATAL Sodium Init: {ex.Message}");
            throw;
        }
    }

    public ShieldProPowerTests(ITestOutputHelper output)
    {
        _output = output;
        _sharedAliceKeys = new LocalKeyMaterial(10);
        _sharedBobKeys = new LocalKeyMaterial(10);
        _sharedAliceManager = ShieldSessionManager.CreateWithCleanupTask();
        _sharedBobManager = ShieldSessionManager.CreateWithCleanupTask();
        _sharedAliceShieldPro = new ShieldPro(_sharedAliceKeys, _sharedAliceManager);
        _sharedBobShieldPro = new ShieldPro(_sharedBobKeys, _sharedBobManager);
    }

    private async Task<(uint aliceSessionId, uint bobSessionId)> EstablishSessionAsync(
        ShieldPro alice, ShieldPro bob, PubKeyExchangeOfType exchangeType)
    {
        (uint aliceId, PubKeyExchange aliceMsg) = await alice.BeginDataCenterPubKeyExchangeAsync(exchangeType);
        (uint bobId, PubKeyExchange bobMsg) = await bob.BeginDataCenterPubKeyExchangeAsync(exchangeType);

        SodiumSecureMemoryHandle? aliceRoot = null, bobRoot = null;
        try
        {
            (_, aliceRoot) = await alice.CompleteDataCenterPubKeyExchangeAsync(aliceId, exchangeType, bobMsg);
            (_, bobRoot) = await bob.CompleteDataCenterPubKeyExchangeAsync(bobId, exchangeType, aliceMsg);
            return (aliceId, bobId);
        }
        finally
        {
            aliceRoot?.Dispose();
            bobRoot?.Dispose();
        }
    }


    // --- Test 1: Concurrent Handshakes (Requires distinct types or IDs not based solely on type) ---
    // NOTE: This test assumes ShieldPro/Manager *can* handle multiple sessions,
    // potentially even of the same type if the keying scheme allows it (e.g., using PeerID).
    // If only one session per type is allowed, this test needs modification or is invalid.
    [Fact(Skip = "Requires session keying beyond just PubKeyExchangeOfType")] // Skip if manager key is just type
    public async Task PowerTest_ConcurrentHandshakes()
    {
        _output.WriteLine("[PowerTest: ConcurrentHandshakes] Running...");
        int concurrencyLevel = 10; // Number of pairs trying to handshake
        var tasks = new List<Task>();
        var exchangeTypeBase = PubKeyExchangeOfType.AppDeviceEphemeralConnect; // Base type

        // Use distinct managers/clients per pair to simulate true concurrency
        var clients = new List<(ShieldPro alice, ShieldPro bob)>();
        for (int i = 0; i < concurrencyLevel; i++)
        {
            var aliceKeys = new LocalKeyMaterial(2);
            var bobKeys = new LocalKeyMaterial(2);
            var aliceMgr = ShieldSessionManager.CreateWithCleanupTask();
            var bobMgr = ShieldSessionManager.CreateWithCleanupTask();
            clients.Add((new ShieldPro(aliceKeys, aliceMgr), new ShieldPro(bobKeys, bobMgr)));
        }

        Stopwatch sw = Stopwatch.StartNew();
        for (int i = 0; i < concurrencyLevel; i++)
        {
            var localI = i; // Capture loop variable
            var clientPair = clients[localI];
            // Simulate different 'types' or ensure session IDs are the main differentiator
            // If type MUST be unique, this test setup is flawed.
            // Assuming session ID makes sessions unique regardless of type for this test:
            PubKeyExchangeOfType currentType = exchangeTypeBase; // Use same type

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    _output.WriteLine($"[Concurrent Handshake {localI}] Starting...");
                    await EstablishSessionAsync(clientPair.alice, clientPair.bob, currentType);
                    _output.WriteLine($"[Concurrent Handshake {localI}] SUCCESS.");
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"[Concurrent Handshake {localI}] FAILED: {ex.Message}");
                    // Optionally rethrow or collect failures
                    Assert.Fail($"Concurrent Handshake {localI} failed: {ex}");
                }
            }));
        }

        await Task.WhenAll(tasks);
        sw.Stop();
        _output.WriteLine(
            $"[PowerTest: ConcurrentHandshakes] Completed {concurrencyLevel} handshakes in {sw.ElapsedMilliseconds} ms.");
        // Assert based on collected failures if any were stored instead of Assert.Fail

        // Cleanup client pairs
        foreach (var clientPair in clients)
        {
            await clientPair.alice.DisposeAsync();
            await clientPair.bob.DisposeAsync();
        }
    }


    // --- Test 2: Message Barrage (Orderly) ---
    [Fact]
    public async Task PowerTest_OrderedMessageBarrage()
    {
        _output.WriteLine("[PowerTest: OrderedMessageBarrage] Running...");
        int messageCount = 100;
        var exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect;

        // Use shared instances for simplicity in this test
        (uint aliceSessionId, uint bobSessionId) =
            await EstablishSessionAsync(_sharedAliceShieldPro, _sharedBobShieldPro, exchangeType);

        Stopwatch sw = Stopwatch.StartNew();
        for (int i = 1; i <= messageCount; i++)
        {
            string message = $"Message {i}/{messageCount}";
            byte[] plaintext = Encoding.UTF8.GetBytes(message);

            // Alice Encrypts
            CipherPayload payload =
                await _sharedAliceShieldPro.ProduceOutboundMessageAsync(aliceSessionId, exchangeType, plaintext);
            Assert.Equal((uint)i, payload.RatchetIndex); // Check index progression

            // Bob Decrypts
            byte[] decrypted =
                await _sharedBobShieldPro.ProcessInboundMessageAsync(bobSessionId, exchangeType, payload);

            // Assert
            Assert.Equal(plaintext, decrypted);
            if (i % 10 == 0) _output.WriteLine($"[Ordered Barrage] Message {i} verified.");
        }

        sw.Stop();
        _output.WriteLine(
            $"[PowerTest: OrderedMessageBarrage] Completed {messageCount} messages roundtrip in {sw.ElapsedMilliseconds} ms.");
    }


    // --- Test 3: Message Barrage with DH Rotation (Placeholder) ---
    [Fact(Skip = "Requires Sender DH Rotation logic in ShieldPro")]
    public async Task PowerTest_BarrageWithDhRotation()
    {
        _output.WriteLine("[PowerTest: BarrageWithDhRotation] Running (SKIPPED)...");
        // Arrange: Establish session
        // Act: Loop sending messages (e.g., 50)
        // --> Inside the loop or ShieldPro, trigger sender DH rotation (e.g., after 20 messages)
        // --> Ensure the payload after rotation includes the DhPublicKey
        // --> Bob receives message with DhPublicKey, ProcessInboundMessage should trigger receiver rotation
        // --> Continue sending/receiving remaining messages
        // Assert: All messages decrypt correctly, including those before/after rotation.
        // Assert: DH keys actually changed on both sides after rotation.
        Assert.True(false, "Sender DH Rotation not implemented");
    }


    // --- Test 4: Out-of-Order Barrage ---
    [Fact]
    public async Task PowerTest_OutOfOrderBarrage()
    {
        _output.WriteLine("[PowerTest: OutOfOrderBarrage] Running...");
        int messageCount = 50; // Keep lower for faster test
        uint cacheWindow = 10; // Test cache limit (adjust based on ShieldChainStep constant)
        var exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect;

        // Create instances with specific cache window (Need to modify ShieldSession constructor or pass via manager if possible)
        // Workaround: Assume default cache is large enough for now, or modify ShieldChainStep default temporarily.
        // Test requires ShieldSession to be created with appropriate cache size. Modifying constructor:
        // public ShieldSession(uint id, Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle localBundleProto, uint cacheWindow = DefaultCacheWindowSize);
        (uint aliceSessionId, uint bobSessionId) =
            await EstablishSessionAsync(_sharedAliceShieldPro, _sharedBobShieldPro, exchangeType);

        var sentMessages = new Dictionary<uint, byte[]>(); // Store index -> plaintext
        var sentPayloads = new List<CipherPayload>();

        _output.WriteLine("[OutOfOrder Barrage] Alice sending messages 1 to {0}...", messageCount);
        Stopwatch swSend = Stopwatch.StartNew();
        for (int i = 1; i <= messageCount; i++)
        {
            string message = $"OoO Message {i}";
            byte[] plaintext = Encoding.UTF8.GetBytes(message);
            CipherPayload payload =
                await _sharedAliceShieldPro.ProduceOutboundMessageAsync(aliceSessionId, exchangeType, plaintext);
            Assert.Equal((uint)i, payload.RatchetIndex);
            sentMessages.Add((uint)i, plaintext);
            sentPayloads.Add(payload);
        }

        swSend.Stop();
        _output.WriteLine($"[OutOfOrder Barrage] Sending finished in {swSend.ElapsedMilliseconds} ms.");


        // Deliver out of order (simple reverse for this test)
        sentPayloads.Reverse();
        _output.WriteLine("[OutOfOrder Barrage] Bob receiving messages in reverse order ({0} to 1)...",
            messageCount);
        Stopwatch swRecv = Stopwatch.StartNew();
        int successfulDecryptions = 0;

        foreach (var payload in sentPayloads)
        {
            try
            {
                byte[] decrypted =
                    await _sharedBobShieldPro.ProcessInboundMessageAsync(bobSessionId, exchangeType, payload);
                // Verify content
                Assert.Equal(sentMessages[payload.RatchetIndex], decrypted);
                successfulDecryptions++;
                if (payload.RatchetIndex % 5 == 0 || payload.RatchetIndex == 1)
                    _output.WriteLine($"[OutOfOrder Barrage] Message {payload.RatchetIndex} verified.");
            }
            catch (ShieldChainStepException ex)
            {
                // Expect failures for messages outside the cache window
                uint expectedMinIndexInCache = (uint)messageCount - cacheWindow + 1; // Rough estimate
                if (payload.RatchetIndex < expectedMinIndexInCache)
                {
                    _output.WriteLine(
                        $"[OutOfOrder Barrage] Expected failure for index {payload.RatchetIndex} (outside cache window): {ex.Message}");
                    Assert.Contains("too old", ex.Message); // Check it's the expected error
                }
                else
                {
                    // Failure *within* expected cache window is an error
                    _output.WriteLine(
                        $"[OutOfOrder Barrage] UNEXPECTED failure for index {payload.RatchetIndex} (should be cached): {ex.Message}");
                    throw; // Rethrow unexpected error
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine(
                    $"[OutOfOrder Barrage] UNEXPECTED non-protocol exception for index {payload.RatchetIndex}: {ex}");
                throw; // Rethrow unexpected error
            }
        }

        swRecv.Stop();

        // Assert: Check that roughly CacheWindow messages succeeded (might be slightly more if indices align well)
        _output.WriteLine(
            $"[PowerTest: OutOfOrderBarrage] Decryption finished in {swRecv.ElapsedMilliseconds} ms. Successful: {successfulDecryptions}/{messageCount}");
        Assert.InRange(successfulDecryptions, (int)cacheWindow - 1,
            (int)cacheWindow + 5); // Allow some leeway around window size
    }

    // --- Test 5: Session Timeout and Cleanup (Difficult to unit test precisely) ---
    [Fact(Skip = "Requires adjusting timing constants or manual cleanup trigger")]
    public async Task PowerTest_SessionTimeout()
    {
        _output.WriteLine("[PowerTest: SessionTimeout] Running (SKIPPED)...");
        // Arrange: Establish session. Modify SessionTimeout constant temporarily?
        // Act: Wait for longer than SessionTimeout.
        // Assert: Encrypt/Decrypt calls throw ShieldChainStepException containing "expired".
        // Act: Trigger cleanup (if possible) or wait for background task.
        // Assert: Session no longer exists in the manager.
        Assert.True(false, "Timeout testing needs adjusted constants or manual trigger.");
    }

    // --- Test 6: Rapid Re-Handshake ---
    [Fact]
    public async Task PowerTest_RapidReHandshake()
    {
        _output.WriteLine("[PowerTest: RapidReHandshake] Running...");
        var exchangeType =
            PubKeyExchangeOfType.AppDeviceEphemeralConnect; // Assume type can be reused if ID differs

        // --- Handshake 1 ---
        _output.WriteLine("[RapidReHandshake] Performing Handshake 1...");
        (uint aliceSessionId1, uint bobSessionId1) =
            await EstablishSessionAsync(_sharedAliceShieldPro, _sharedBobShieldPro, exchangeType);
        _output.WriteLine(
            $"[RapidReHandshake] Handshake 1 complete. Alice ID: {aliceSessionId1}, Bob ID: {bobSessionId1}");

        // --- Message Exchange 1 ---
        _output.WriteLine("[RapidReHandshake] Exchanging message on session 1...");
        var msg1 = Encoding.UTF8.GetBytes("Message on session 1");
        var payload1 = await _sharedAliceShieldPro.ProduceOutboundMessageAsync(aliceSessionId1, exchangeType, msg1);
        var decrypted1 =
            await _sharedBobShieldPro.ProcessInboundMessageAsync(bobSessionId1, exchangeType, payload1);
        Assert.Equal(msg1, decrypted1);

        // --- Handshake 2 (Immediately After) ---
        _output.WriteLine("[RapidReHandshake] Performing Handshake 2...");
        // IMPORTANT: This assumes that calling Begin again *for the same type* is allowed
        // and will create a *new* session ID, potentially replacing or coexisting with the old one.
        // If only one session per type is allowed, this test needs adjustment.
        (uint aliceSessionId2, uint bobSessionId2) =
            await EstablishSessionAsync(_sharedAliceShieldPro, _sharedBobShieldPro, exchangeType);
        _output.WriteLine(
            $"[RapidReHandshake] Handshake 2 complete. Alice ID: {aliceSessionId2}, Bob ID: {bobSessionId2}");
        Assert.NotEqual(aliceSessionId1, aliceSessionId2); // Should get new IDs
        Assert.NotEqual(bobSessionId1, bobSessionId2);

        // --- Message Exchange 2 ---
        _output.WriteLine("[RapidReHandshake] Exchanging message on session 2...");
        var msg2 = Encoding.UTF8.GetBytes("Message on session 2");
        // Use NEW session IDs
        var payload2 = await _sharedAliceShieldPro.ProduceOutboundMessageAsync(aliceSessionId2, exchangeType, msg2);
        var decrypted2 =
            await _sharedBobShieldPro.ProcessInboundMessageAsync(bobSessionId2, exchangeType, payload2);
        Assert.Equal(msg2, decrypted2);

        // --- Optional: Check if old session is still usable (depends on manager logic) ---
        _output.WriteLine("[RapidReHandshake] Attempting message on session 1 again...");
        try
        {
            var msg3 = Encoding.UTF8.GetBytes("Message on session 1 again");
            var payload3 =
                await _sharedAliceShieldPro.ProduceOutboundMessageAsync(aliceSessionId1, exchangeType, msg3);
            var decrypted3 =
                await _sharedBobShieldPro.ProcessInboundMessageAsync(bobSessionId1, exchangeType, payload3);
            Assert.Equal(msg3, decrypted3);
            _output.WriteLine("[RapidReHandshake] Session 1 still usable (as expected by default).");
        }
        catch (ShieldChainStepException ex)
        {
            _output.WriteLine($"[RapidReHandshake] Session 1 failed as expected (if replaced): {ex.Message}");
            // Add assertion here if session replacement is the expected behavior
        }

        _output.WriteLine("[PowerTest: RapidReHandshake] SUCCESS.");
    }


    // --- IAsyncDisposable for Test Class ---
    public async ValueTask DisposeAsync()
    {
        await _sharedAliceShieldPro.DisposeAsync();
        await _sharedBobShieldPro.DisposeAsync();
        // Managers disposed via ShieldPro disposal
        _sharedAliceKeys.Dispose();
        _sharedBobKeys.Dispose();
        GC.SuppressFinalize(this);
    }
}*/