using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography; // For AuthenticationTagMismatchException
using System.Text;
using System.Threading.Tasks;
using Ecliptix.Core.Protocol; // Your ShieldPro namespace
using Ecliptix.Core.Protocol.Utilities; // For ShieldChainStepException if needed
using Ecliptix.Protobuf.CipherPayload; // Your CipherPayload namespace
using Ecliptix.Protobuf.PubKeyExchange; // Your PubKeyExchange namespace

// Assuming your test class setup initializes _aliceShieldPro, _bobShieldPro,
// _aliceSessionId, _bobSessionId, and _exchangeType correctly via [TestInitialize]

[TestClass]
public class ShieldProDoubleRatchetTests // Or your actual test class name
{
    // --- Your Fields ---
    // Make sure these are correctly initialized in your [TestInitialize]
    private ShieldPro _aliceShieldPro;
    private ShieldPro _bobShieldPro;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private PubKeyExchangeOfType _exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect; // Example
    // --- End Fields ---

    public TestContext TestContext { get; set; }
    private void WriteLine(string message) => TestContext.WriteLine(message);

    // --- Your [TestInitialize] method goes here ---
    // Ensure it performs the handshake and sets the session IDs correctly
    [TestInitialize]
    public async Task InitializeAsync()
    {
        WriteLine("[TestInitialize] Setting up Alice and Bob...");
        // Create key materials (replace with your LocalKeyMaterial setup)
        var aliceMaterial = new LocalKeyMaterial(1);
        var bobMaterial = new LocalKeyMaterial(2);

        // Create ShieldPro instances
        _aliceShieldPro = new ShieldPro(aliceMaterial);
        _bobShieldPro = new ShieldPro(bobMaterial);

        // Perform X3DH handshake
        WriteLine("[TestInitialize] Performing X3DH Handshake...");
        var (aliceSessionId, aliceInitialMsg) = await _aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
        _aliceSessionId = aliceSessionId;

        var (bobSessionId, bobResponseMsg) =
            await _bobShieldPro.ProcessAndRespondToPubKeyExchangeAsync(aliceInitialMsg);
        _bobSessionId = bobSessionId;

        await _aliceShieldPro.CompletePubKeyExchangeAsync(_aliceSessionId, _exchangeType, bobResponseMsg);

        WriteLine(
            $"[TestInitialize] Handshake Complete. Alice Session: {_aliceSessionId}, Bob Session: {_bobSessionId}");
    }
    // --- End [TestInitialize] ---

    // --- Your [TestCleanup] method goes here ---
    [TestCleanup]
    public async Task CleanupAsync()
    {
        WriteLine("[Cleanup] Disposing test resources...");
        if (_aliceShieldPro != null) await _aliceShieldPro.DisposeAsync();
        if (_bobShieldPro != null) await _bobShieldPro.DisposeAsync();
        WriteLine("[Cleanup] Test resources disposed.");
    }
   
   [TestMethod]
    [Timeout(60000)] // 1 minute
    public async Task Ratchet_Parallel50Sessions_ConversationLike_Succeeds()
    {
        WriteLine("[Test: Ratchet_Parallel50Sessions_ConversationLike] Running...");
        const int sessionCount = 50;
        const int messagesPerParty = 20; // 20 Alice + 20 Bob = 40 per session
        const int burstSize = 5; // Alternate every 5 messages to trigger DH ratchets
        var results = new ConcurrentBag<(int SessionId, string Error)>();

        var sessionTasks = Enumerable.Range(1, sessionCount).Select(async sessionId =>
        {
            try
            {
                // Initialize key materials
                var aliceMaterial = new LocalKeyMaterial((uint)sessionId * 2 - 1);
                var bobMaterial = new LocalKeyMaterial((uint)sessionId * 2);

                // Create ShieldPro instances
                 var aliceShieldPro = new ShieldPro(aliceMaterial);
                 var bobShieldPro = new ShieldPro(bobMaterial);

                // Perform X3DH handshake
                var (aliceSessionId, aliceInitialMsg) = await aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
                var (bobSessionId, bobResponseMsg) = await bobShieldPro.ProcessAndRespondToPubKeyExchangeAsync(aliceInitialMsg);
                await aliceShieldPro.CompletePubKeyExchangeAsync(aliceSessionId, _exchangeType, bobResponseMsg);

                // Track DH ratchets and messages
                int aliceDhRatchetCount = 0;
                int bobDhRatchetCount = 0;
                var aliceMessages = new List<(int Id, byte[] Plaintext, CipherPayload Payload)>(messagesPerParty);
                var bobMessages = new List<(int Id, byte[] Plaintext, CipherPayload Payload)>(messagesPerParty);

                // Simulate conversation with alternating bursts
                while (aliceMessages.Count < messagesPerParty || bobMessages.Count < messagesPerParty)
                {
                    // Alice sends up to burstSize messages
                    for (int i = 0; i < burstSize && aliceMessages.Count < messagesPerParty; i++)
                    {
                        int msgId = aliceMessages.Count + 1;
                        var plaintext = Encoding.UTF8.GetBytes($"Session {sessionId}: Alice msg {msgId}");
                        var payload = await aliceShieldPro.ProduceOutboundMessageAsync(aliceSessionId, _exchangeType, plaintext);
                        if (!payload.DhPublicKey.IsEmpty) aliceDhRatchetCount++;
                        aliceMessages.Add((msgId, plaintext, payload));
                    }

                    // Bob decrypts Alice’s latest burst
                    var aliceBurst = aliceMessages.TakeLast(Math.Min(burstSize, aliceMessages.Count)).ToList();
                    foreach (var (id, plaintext, payload) in aliceBurst)
                    {
                        var decrypted = await bobShieldPro.ProcessInboundMessageAsync(bobSessionId, _exchangeType, payload);
                        CollectionAssert.AreEqual(plaintext, decrypted, $"Session {sessionId}: Bob decrypt failed at Alice msg {id}");
                    }

                    // Bob sends up to burstSize messages
                    for (int i = 0; i < burstSize && bobMessages.Count < messagesPerParty; i++)
                    {
                        int msgId = bobMessages.Count + 1;
                        var plaintext = Encoding.UTF8.GetBytes($"Session {sessionId}: Bob msg {msgId}");
                        var payload = await bobShieldPro.ProduceOutboundMessageAsync(bobSessionId, _exchangeType, plaintext);
                        if (!payload.DhPublicKey.IsEmpty) bobDhRatchetCount++;
                        bobMessages.Add((msgId, plaintext, payload));
                    }

                    // Alice decrypts Bob’s latest burst
                    var bobBurst = bobMessages.TakeLast(Math.Min(burstSize, bobMessages.Count)).ToList();
                    foreach (var (id, plaintext, payload) in bobBurst)
                    {
                        var decrypted = await aliceShieldPro.ProcessInboundMessageAsync(aliceSessionId, _exchangeType, payload);
                        CollectionAssert.AreEqual(plaintext, decrypted, $"Session {sessionId}: Alice decrypt failed at Bob msg {id}");
                    }
                }

                // Verify DH ratchets
                if (aliceDhRatchetCount == 0 || bobDhRatchetCount == 0)
                {
                    results.Add((sessionId, $"No DH ratchet in session {sessionId} (Alice: {aliceDhRatchetCount}, Bob: {bobDhRatchetCount})"));
                }

                // Verify message counts
                if (aliceMessages.Count != messagesPerParty || bobMessages.Count != messagesPerParty)
                {
                    results.Add((sessionId, $"Message count mismatch in session {sessionId} (Alice: {aliceMessages.Count}, Bob: {bobMessages.Count})"));
                }
            }
            catch (Exception ex)
            {
                results.Add((sessionId, $"Session {sessionId} failed: {ex.Message}"));
            }
        }).ToList();

        // Run sessions with controlled parallelism
        await Parallel.ForEachAsync(sessionTasks, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, async (task, ct) => await task);

        // Check results
        if (results.Any())
        {
            foreach (var (id, error) in results)
            {
                WriteLine($"[Error] {error}");
            }
            Assert.Fail($"Parallel test failed with {results.Count} errors.");
        }

        WriteLine($"[Test] SUCCESS - All {sessionCount} sessions completed {messagesPerParty * 2} messages each without errors.");
    }


    [TestMethod]
    public async Task Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations_Succeeds()
    {
        WriteLine("[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] Running...");
        const int iterationCount = 506;

        uint aliceMessagesSent = 0;
        uint bobMessagesSent = 0;

        for (int i = 1; i <= iterationCount; i++)
        {
            WriteLine($"\n--- Starting Iteration {i} ---");

            // Alice sends to Bob
            string aliceMessage = $"Message {i} from Alice to Bob (Overall #{aliceMessagesSent + 1})";
            byte[] alicePlaintextBytes = Encoding.UTF8.GetBytes(aliceMessage);
            WriteLine($"[Iteration {i}] Alice (Session {_aliceSessionId}) encrypting #{aliceMessagesSent + 1}...");
            CipherPayload alicePayload =
                await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, alicePlaintextBytes);
            bool aliceSentNewKey = !alicePayload.DhPublicKey.IsEmpty;
            WriteLine(
                $"[Iteration {i}] Alice sent message with Index: {alicePayload.RatchetIndex}, DH Key: {aliceSentNewKey}");

            // Bob receives from Alice
            WriteLine($"[Iteration {i}] Bob (Session {_bobSessionId}) decrypting Alice's message {i}...");
            byte[] bobDecryptedBytes =
                await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, alicePayload);
            CollectionAssert.AreEqual(alicePlaintextBytes, bobDecryptedBytes,
                $"Bob decrypted Alice's message mismatch at iteration {i}");
            WriteLine($"[Iteration {i}] Bob successfully decrypted Alice's message {i}.");
            aliceMessagesSent++;

            // Bob sends to Alice
            string bobMessage = $"Response {i} from Bob to Alice (Overall #{bobMessagesSent + 1})";
            byte[] bobPlaintextBytes = Encoding.UTF8.GetBytes(bobMessage);
            WriteLine($"[Iteration {i}] Bob (Session {_bobSessionId}) encrypting #{bobMessagesSent + 1}...");
            CipherPayload bobPayload =
                await _bobShieldPro.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType, bobPlaintextBytes);
            bool bobSentNewKey = !bobPayload.DhPublicKey.IsEmpty;
            WriteLine(
                $"[Iteration {i}] Bob sent response with Index: {bobPayload.RatchetIndex}, DH Key: {bobSentNewKey}");

            // Alice receives from Bob
            WriteLine($"[Iteration {i}] Alice (Session {_aliceSessionId}) decrypting Bob's response {i}...");
            byte[] aliceDecryptedBytes =
                await _aliceShieldPro.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType, bobPayload);
            CollectionAssert.AreEqual(bobPlaintextBytes, aliceDecryptedBytes,
                $"Alice decrypted Bob's response mismatch at iteration {i}");
            WriteLine($"[Iteration {i}] Alice successfully decrypted Bob's response {i}.");
            bobMessagesSent++;

            WriteLine($"[Iteration {i}] Bidirectional exchange completed.");
        }

        Assert.AreEqual((uint)iterationCount, aliceMessagesSent, "Alice message count mismatch.");
        Assert.AreEqual((uint)iterationCount, bobMessagesSent, "Bob message count mismatch.");
        WriteLine($"\n[Test] SUCCESS - All {iterationCount} iterations completed without exceptions.");
    }
}