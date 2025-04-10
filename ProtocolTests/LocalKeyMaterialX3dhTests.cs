using System.Collections.Concurrent;
using System.Text;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ProtocolTests;

[TestClass]
public class ShieldProDoubleRatchetTests : IAsyncDisposable
{
    private TestContext? _testContextInstance;

    public TestContext TestContext
    {
        get => _testContextInstance ?? throw new InvalidOperationException("TestContext not set.");
        set => _testContextInstance = value;
    }

    private void WriteLine(string message) => TestContext?.WriteLine(message);

    private LocalKeyMaterial _aliceKeys = null!;
    private LocalKeyMaterial _bobKeys = null!;
    private ShieldSessionManager _aliceSessionManager = null!;
    private ShieldSessionManager _bobSessionManager = null!;
    private ShieldPro _aliceShieldPro = null!;
    private ShieldPro _bobShieldPro = null!;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private PubKeyExchangeOfType _exchangeType;

    private const uint DhRotationInterval = 50; // Must match ShieldSession

    static ShieldProDoubleRatchetTests()
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

    public ShieldProDoubleRatchetTests()
    {
    }

    private static bool CompareSecureHandles(SodiumSecureMemoryHandle? handleA, SodiumSecureMemoryHandle? handleB)
    {
        if (ReferenceEquals(handleA, handleB)) return true;
        if (handleA == null || handleB == null) return false;
        if (handleA.IsInvalid || handleB.IsInvalid) return handleA.IsInvalid && handleB.IsInvalid;
        if (handleA.Length != handleB.Length) return false;
        if (handleA.Length == 0) return true;

        byte[]? bytesAHeap = null;
        byte[]? bytesBHeap = null;
        try
        {
            bytesAHeap = new byte[handleA.Length];
            bytesBHeap = new byte[handleB.Length];
            handleA.Read(bytesAHeap.AsSpan());
            handleB.Read(bytesBHeap.AsSpan());
            return bytesAHeap.SequenceEqual(bytesBHeap);
        }
        finally
        {
            if (bytesAHeap != null) SodiumInterop.SecureWipe(bytesAHeap);
            if (bytesBHeap != null) SodiumInterop.SecureWipe(bytesBHeap);
        }
    }

    [TestInitialize]
    public async Task InitializeAsync()
    {
        _aliceKeys = new LocalKeyMaterial(5);
        _bobKeys = new LocalKeyMaterial(5);
        _aliceSessionManager = ShieldSessionManager.CreateWithCleanupTask();
        _bobSessionManager = ShieldSessionManager.CreateWithCleanupTask();
        _aliceShieldPro = new ShieldPro(_aliceKeys, _aliceSessionManager);
        _bobShieldPro = new ShieldPro(_bobKeys, _bobSessionManager);
        _exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect;

        (uint aliceSessionId, PubKeyExchange aliceInitialMessage) =
            await _aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
        _aliceSessionId = aliceSessionId;

        (uint bobSessionId, PubKeyExchange bobResponseMessage) =
            await _bobShieldPro.ProcessAndRespondToPubKeyExchangeAsync(aliceInitialMessage);
        _bobSessionId = bobSessionId;

        await _aliceShieldPro.CompletePubKeyExchangeAsync(_aliceSessionId, _exchangeType, bobResponseMessage);

        var aliceSession = _aliceSessionManager.GetSessionOrThrow(_aliceSessionId, _exchangeType);
        var bobSession = _bobSessionManager.GetSessionOrThrow(_bobSessionId, _exchangeType);
        Assert.AreEqual(PubKeyExchangeState.Complete, aliceSession.State);
        Assert.AreEqual(PubKeyExchangeState.Complete, bobSession.State);
    }

    [TestMethod]
    public async Task Ratchet_SendReceiveSingleMessage_Succeeds()
    {
        const string message = "Hello Bob! This is the first DR message.";
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);

        CipherPayload payload =
            await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, plaintextBytes);
        Assert.AreEqual(1u, payload.RatchetIndex, "First message index should be 1.");
        Assert.IsTrue(payload.DhPublicKey.IsEmpty, "No DH rotation on first message.");

        byte[] decryptedBytes = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload);
        string decrypted = Encoding.UTF8.GetString(decryptedBytes);
        Assert.AreEqual(message, decrypted, "Decrypted message mismatch.");
    }

    [TestMethod]
public async Task Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations_Succeeds()
{
    WriteLine("[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] Running...");
    const int iterationCount = 153;
    const uint DhRotationInterval = 50;

    uint aliceMessagesSent = 0;
    uint bobMessagesSent = 0;
    uint expectedAliceIndex = 0;
    uint expectedBobIndex = 0;

    for (int i = 1; i <= iterationCount; i++)
    {
        WriteLine($"\n--- Starting Iteration {i} ---");

        // Alice sends to Bob
        string aliceMessage = $"Message {i} from Alice to Bob (Overall #{aliceMessagesSent + 1})";
        byte[] alicePlaintextBytes = Encoding.UTF8.GetBytes(aliceMessage);
        WriteLine($"[Iteration {i}] Alice (Session {_aliceSessionId}) encrypting #{aliceMessagesSent + 1}...");

        CipherPayload alicePayload = await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, alicePlaintextBytes);
        bool aliceRotationOccurred = !alicePayload.DhPublicKey.IsEmpty;

        // Update expected index for Alice
        expectedAliceIndex++;
        if (aliceRotationOccurred)
        {
            expectedAliceIndex = 1;
        }
        WriteLine($"[Iteration {i}] Alice Payload Details - Index: {alicePayload.RatchetIndex}, DH Key Sent: {aliceRotationOccurred}");
        Assert.AreEqual(expectedAliceIndex, alicePayload.RatchetIndex, $"Alice index mismatch at message #{aliceMessagesSent + 1}. Expected: {expectedAliceIndex}");

        WriteLine($"[Iteration {i}] Bob (Session {_bobSessionId}) decrypting Alice's message {i} (Payload Index {alicePayload.RatchetIndex})...");
        byte[] bobDecryptedBytes = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, alicePayload);
        CollectionAssert.AreEqual(alicePlaintextBytes, bobDecryptedBytes, $"Bob decrypted Alice's message mismatch at iteration {i}");
        WriteLine($"[Iteration {i}] Bob successfully decrypted Alice's message {i}.");
        aliceMessagesSent++;

        // Bob sends to Alice
        string bobMessage = $"Response {i} from Bob to Alice (Overall #{bobMessagesSent + 1})";
        byte[] bobPlaintextBytes = Encoding.UTF8.GetBytes(bobMessage);
        WriteLine($"[Iteration {i}] Bob (Session {_bobSessionId}) encrypting #{bobMessagesSent + 1}...");

        CipherPayload bobPayload = await _bobShieldPro.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType, bobPlaintextBytes);
        bool bobRotationOccurred = !bobPayload.DhPublicKey.IsEmpty;

        // Update expected index for Bob
        expectedBobIndex++;
        if (bobRotationOccurred)
        {
            expectedBobIndex = 1;
        }
        WriteLine($"[Iteration {i}] Bob Payload Details - Index: {bobPayload.RatchetIndex}, DH Key Sent: {bobRotationOccurred}");
        Assert.AreEqual(expectedBobIndex, bobPayload.RatchetIndex, $"Bob index mismatch at message #{bobMessagesSent + 1}. Expected: {expectedBobIndex}");

        WriteLine($"[Iteration {i}] Alice (Session {_aliceSessionId}) decrypting Bob's response {i} (Payload Index {bobPayload.RatchetIndex})...");
        byte[] aliceDecryptedBytes = await _aliceShieldPro.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType, bobPayload);
        CollectionAssert.AreEqual(bobPlaintextBytes, aliceDecryptedBytes, $"Alice decrypted Bob's response mismatch at iteration {i}");
        WriteLine($"[Iteration {i}] Alice successfully decrypted Bob's response {i}.");
        bobMessagesSent++;

        WriteLine($"[Iteration {i}] Bidirectional exchange completed.");
    }

    Assert.AreEqual((uint)iterationCount, aliceMessagesSent, "Alice message count mismatch.");
    Assert.AreEqual((uint)iterationCount, bobMessagesSent, "Bob message count mismatch.");
    WriteLine($"\n[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] SUCCESS - All {iterationCount} iterations completed.");
}

    [TestMethod]
    public async Task Ratchet_ChaoticParallelMessageExchange_500MessagesEach_WithDHRotation_Succeeds()
    {
        WriteLine("[Test: Ratchet_ChaoticParallelMessageExchange_500MessagesEach_WithDHRotation] Running...");
        Stopwatch sw = Stopwatch.StartNew();

        const int messageCount = 500;
        Random random = new();

        ConcurrentDictionary<int, byte[]> aliceSentMessages = new();
        ConcurrentDictionary<int, CipherPayload> aliceSentPayloads = new();
        ConcurrentDictionary<int, byte[]> bobSentMessages = new();
        ConcurrentDictionary<int, CipherPayload> bobSentPayloads = new();
        ConcurrentDictionary<int, byte[]?> bobDecryptedFromAlice = new();
        ConcurrentDictionary<int, byte[]?> aliceDecryptedFromBob = new();

        // Phase 1: Chaotic Sending
        WriteLine($"Phase 1: Alice and Bob sending {messageCount} messages each chaotically...");
        List<Task> sendTasks = new();
        var sendOrder = Enumerable.Range(0, messageCount * 2)
            .Select(i => i < messageCount ? ('A', i) : ('B', i - messageCount))
            .OrderBy(_ => random.Next())
            .ToList();

        foreach (var (senderType, msgIndex) in sendOrder)
        {
            sendTasks.Add(Task.Run(async () =>
            {
                await Task.Delay(random.Next(1, 10));
                if (senderType == 'A')
                {
                    string message = $"Chaotic message A->B {msgIndex + 1}";
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);
                    aliceSentMessages[msgIndex] = plaintextBytes;
                    try
                    {
                        CipherPayload payload =
                            await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                                plaintextBytes);
                        aliceSentPayloads[msgIndex] = payload;
                    }
                    catch (Exception ex)
                    {
                        WriteLine($"[ERROR] Alice send {msgIndex + 1}: {ex.Message}");
                    }
                }
                else
                {
                    string message = $"Chaotic message B->A {msgIndex + 1}";
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);
                    bobSentMessages[msgIndex] = plaintextBytes;
                    try
                    {
                        CipherPayload payload =
                            await _bobShieldPro.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType,
                                plaintextBytes);
                        bobSentPayloads[msgIndex] = payload;
                    }
                    catch (Exception ex)
                    {
                        WriteLine($"[ERROR] Bob send {msgIndex + 1}: {ex.Message}");
                    }
                }
            }));
        }

        await Task.WhenAll(sendTasks);
        WriteLine($"Phase 1 Complete: All {messageCount * 2} messages produced in {sw.ElapsedMilliseconds}ms.");

        sw.Restart();

        // Phase 2: Chaotic Receiving
        WriteLine($"Phase 2: Alice and Bob decrypting {messageCount} messages each chaotically...");
        List<Task> receiveTasks = new();
        var receiveOrder = Enumerable.Range(0, messageCount * 2)
            .Select(i => i < messageCount ? ('B', i) : ('A', i - messageCount))
            .OrderBy(_ => random.Next())
            .ToList();

        foreach (var (receiverType, msgIndex) in receiveOrder)
        {
            receiveTasks.Add(Task.Run(async () =>
            {
                await Task.Delay(random.Next(1, 10));
                if (receiverType == 'B')
                {
                    if (aliceSentPayloads.TryGetValue(msgIndex, out var payload))
                    {
                        try
                        {
                            byte[] decryptedBytes =
                                await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload);
                            bobDecryptedFromAlice[msgIndex] = decryptedBytes;
                        }
                        catch (Exception ex)
                        {
                            WriteLine(
                                $"[ERROR] Bob receive Alice's {msgIndex + 1} (Idx: {payload?.RatchetIndex}): {ex.Message}");
                            bobDecryptedFromAlice[msgIndex] = null;
                        }
                    }
                }
                else
                {
                    if (bobSentPayloads.TryGetValue(msgIndex, out var payload))
                    {
                        try
                        {
                            byte[] decryptedBytes =
                                await _aliceShieldPro.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType,
                                    payload);
                            aliceDecryptedFromBob[msgIndex] = decryptedBytes;
                        }
                        catch (Exception ex)
                        {
                            WriteLine(
                                $"[ERROR] Alice receive Bob's {msgIndex + 1} (Idx: {payload?.RatchetIndex}): {ex.Message}");
                            aliceDecryptedFromBob[msgIndex] = null;
                        }
                    }
                }
            }));
        }

        await Task.WhenAll(receiveTasks);
        WriteLine($"Phase 2 Complete: All {messageCount * 2} messages processed in {sw.ElapsedMilliseconds}ms.");

        // Phase 3: Validation
        WriteLine("Phase 3: Validating all decrypted messages...");
        int validationErrors = 0;
        Parallel.For(0, messageCount, i =>
        {
            if (!aliceSentMessages.TryGetValue(i, out var originalAlice) ||
                !bobDecryptedFromAlice.TryGetValue(i, out var decryptedByBob) || decryptedByBob == null ||
                !originalAlice.SequenceEqual(decryptedByBob))
            {
                WriteLine($"[VALIDATION FAIL] Bob's decryption of Alice's message {i + 1}");
                Interlocked.Increment(ref validationErrors);
            }

            if (!bobSentMessages.TryGetValue(i, out var originalBob) ||
                !aliceDecryptedFromBob.TryGetValue(i, out var decryptedByAlice) || decryptedByAlice == null ||
                !originalBob.SequenceEqual(decryptedByAlice))
            {
                WriteLine($"[VALIDATION FAIL] Alice's decryption of Bob's message {i + 1}");
                Interlocked.Increment(ref validationErrors);
            }
        });

        Assert.AreEqual(0, validationErrors, $"Found {validationErrors} validation errors after chaotic exchange.");
        WriteLine(
            $"[Test: Ratchet_ChaoticParallelMessageExchange_500MessagesEach_WithDHRotation] SUCCESS - All {messageCount * 2} messages validated.");
    }

    public async ValueTask DisposeAsync()
    {
        WriteLine("[Cleanup] Disposing test resources...");
        var disposeTasks = new List<Task>();
        if (_aliceShieldPro != null) disposeTasks.Add(_aliceShieldPro.DisposeAsync().AsTask());
        if (_bobShieldPro != null) disposeTasks.Add(_bobShieldPro.DisposeAsync().AsTask());

        try
        {
            await Task.WhenAll(disposeTasks);
        }
        catch (Exception ex)
        {
            WriteLine($"[Cleanup Error] {ex.Message}");
        }

        _aliceKeys?.Dispose();
        _bobKeys?.Dispose();
        _aliceShieldPro = null!;
        _bobShieldPro = null!;
        _aliceSessionManager = null!;
        _bobSessionManager = null!;
        _aliceKeys = null!;
        _bobKeys = null!;
        WriteLine("[Cleanup] Test resources disposed.");
        GC.SuppressFinalize(this);
    }

    [TestCleanup]
    public async Task CleanupAsync()
    {
        await DisposeAsync();
    }
}