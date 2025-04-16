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
        var aliceMaterial = LocalKeyMaterial.Create(1).Unwrap();
        var bobMaterial = LocalKeyMaterial.Create(2).Unwrap();

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

        await _aliceShieldPro.CompleteDataCenterPubKeyExchangeAsync(_aliceSessionId, _exchangeType, bobResponseMsg);

        WriteLine(
            $"[TestInitialize] Handshake Complete. Alice Session: {_aliceSessionId}, Bob Session: {_bobSessionId}");
    }

    [TestMethod]
    public async Task SingleSession_DHRatchet_TriggersAtInterval()
    {
        var alice = new ShieldPro(LocalKeyMaterial.Create(1).Unwrap());
        var bob = new ShieldPro(LocalKeyMaterial.Create(2).Unwrap());
        var (aliceId, aliceMsg) =
            await alice.BeginDataCenterPubKeyExchangeAsync(PubKeyExchangeOfType.AppDeviceEphemeralConnect);
        var (bobId, bobMsg) = await bob.ProcessAndRespondToPubKeyExchangeAsync(aliceMsg);
        await alice.CompleteDataCenterPubKeyExchangeAsync(aliceId, PubKeyExchangeOfType.AppDeviceEphemeralConnect,
            bobMsg);

        bool ratchetTriggered = false;
        for (int i = 1; i <= 10; i++)
        {
            var msg = Encoding.UTF8.GetBytes($"Msg {i}");
            var cipher =
                await alice.ProduceOutboundMessageAsync(aliceId, PubKeyExchangeOfType.AppDeviceEphemeralConnect, msg);
            if (!cipher.DhPublicKey.IsEmpty)
            {
                ratchetTriggered = true;
                WriteLine($"Ratchet triggered at message {i}");
            }

            await bob.ProcessInboundMessageAsync(bobId, PubKeyExchangeOfType.AppDeviceEphemeralConnect, cipher);
        }

        Assert.IsTrue(ratchetTriggered, "DH ratchet did not trigger at interval 10.");
        await alice.DisposeAsync();
        await bob.DisposeAsync();
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
    public async Task Ratchet_Parallel50Sessions_ConversationLike_Succeeds()
    {
        WriteLine("[Test: Ratchet_Parallel50Sessions_ConversationLike] Starting...");
        const int sessionCount = 50;
        const int messagesPerSession = 20;
        var sessionPairs = new List<(ShieldPro Alice, ShieldPro Bob, uint AliceSessionId, uint BobSessionId)>();
        var dhRatchetCounts = new ConcurrentDictionary<int, (int AliceCount, int BobCount)>();

        // Setup
        WriteLine($"[Setup] Creating {sessionCount} session pairs...");
        for (int i = 0; i < sessionCount; i++)
        {
            var testSessionId = i + 1;
            WriteLine($"[Setup] Initializing pair {testSessionId}...");

            try
            {
                var aliceMaterial = LocalKeyMaterial.Create((uint)(i * 2 + 1)).Unwrap();
                var bobMaterial = LocalKeyMaterial.Create((uint)(i * 2 + 2)).Unwrap();
                var alice = new ShieldPro(aliceMaterial);
                var bob = new ShieldPro(bobMaterial);

                var (aliceSessionId, aliceInitialMsg) =
                    await alice.BeginDataCenterPubKeyExchangeAsync(PubKeyExchangeOfType.AppDeviceEphemeralConnect);
                var (bobSessionId, bobResponseMsg) = await bob.ProcessAndRespondToPubKeyExchangeAsync(aliceInitialMsg);
                await alice.CompleteDataCenterPubKeyExchangeAsync(aliceSessionId,
                    PubKeyExchangeOfType.AppDeviceEphemeralConnect, bobResponseMsg);

                WriteLine($"[Setup] Pair {testSessionId}: Alice Session {aliceSessionId}, Bob Session {bobSessionId}");
                sessionPairs.Add((alice, bob, aliceSessionId, bobSessionId));
            }
            catch (Exception ex)
            {
                Assert.Fail($"[Setup] Pair {testSessionId} handshake failed: {ex.Message}");
            }
        }

        // Run conversations
        WriteLine($"[Test] Running {sessionCount} conversations with {messagesPerSession} messages each...");
        var tasks = new List<Task>();
        foreach (var (alice, bob, aliceSessionId, bobSessionId) in sessionPairs)
        {
            var testSessionId = sessionPairs.IndexOf((alice, bob, aliceSessionId, bobSessionId)) + 1;
            tasks.Add(Task.Run(async () =>
            {
                int aliceDhRatchets = 0;
                int bobDhRatchets = 0;

                WriteLine($"[Session {testSessionId}] Starting conversation...");
                for (int j = 0; j < messagesPerSession; j++)
                {
                    var msgNumber = j + 1;
                    try
                    {
                        // Alice sends
                        var aliceMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Alice msg {msgNumber}");
                        WriteLine($"[Session {testSessionId}] Alice sending msg {msgNumber}...");
                        var aliceCipher = await alice.ProduceOutboundMessageAsync(aliceSessionId,
                            PubKeyExchangeOfType.AppDeviceEphemeralConnect, aliceMsg);
                        WriteLine(
                            $"[Session {testSessionId}] Alice msg {msgNumber}: Index={aliceCipher.RatchetIndex}, DHKey={(aliceCipher.DhPublicKey.IsEmpty ? "None" : Convert.ToHexString(aliceCipher.DhPublicKey.ToByteArray()))}");
                        if (!aliceCipher.DhPublicKey.IsEmpty)
                        {
                            aliceDhRatchets++;
                            WriteLine(
                                $"[Session {testSessionId}] Alice DH ratchet at msg {msgNumber}, Index {aliceCipher.RatchetIndex}");
                        }

                        var bobPlaintext = await bob.ProcessInboundMessageAsync(bobSessionId,
                            PubKeyExchangeOfType.AppDeviceEphemeralConnect, aliceCipher);
                        CollectionAssert.AreEqual(aliceMsg, bobPlaintext,
                            $"[Session {testSessionId}] Bob failed to decrypt Alice msg {msgNumber}");

                        // Bob sends
                        var bobMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Bob msg {msgNumber}");
                        WriteLine($"[Session {testSessionId}] Bob sending msg {msgNumber}...");
                        var bobCipher = await bob.ProduceOutboundMessageAsync(bobSessionId,
                            PubKeyExchangeOfType.AppDeviceEphemeralConnect, bobMsg);
                        WriteLine(
                            $"[Session {testSessionId}] Bob msg {msgNumber}: Index={bobCipher.RatchetIndex}, DHKey={(bobCipher.DhPublicKey.IsEmpty ? "None" : Convert.ToHexString(bobCipher.DhPublicKey.ToByteArray()))}");
                        if (!bobCipher.DhPublicKey.IsEmpty)
                        {
                            bobDhRatchets++;
                            WriteLine(
                                $"[Session {testSessionId}] Bob DH ratchet at msg {msgNumber}, Index {bobCipher.RatchetIndex}");
                        }

                        var alicePlaintext = await alice.ProcessInboundMessageAsync(aliceSessionId,
                            PubKeyExchangeOfType.AppDeviceEphemeralConnect, bobCipher);
                        CollectionAssert.AreEqual(bobMsg, alicePlaintext,
                            $"[Session {testSessionId}] Alice failed to decrypt Bob msg {msgNumber}");
                    }
                    catch (Exception ex)
                    {
                        WriteLine(
                            $"[Session {testSessionId}] Error in msg {msgNumber}: {ex.Message} ({ex.GetType().Name})");
                        throw;
                    }
                }

                dhRatchetCounts[testSessionId] = (aliceDhRatchets, bobDhRatchets);
                WriteLine(
                    $"[Session {testSessionId}] Completed: Alice DH Ratchets = {aliceDhRatchets}, Bob DH Ratchets = {bobDhRatchets}");
            }));
        }

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (Exception ex)
        {
            Assert.Fail($"[Test] Parallel execution failed: {ex.Message}");
        }

        // Verify
        WriteLine("[Test] Verifying DH ratchet counts...");
        for (int i = 1; i <= sessionCount; i++)
        {
            if (!dhRatchetCounts.TryGetValue(i, out var counts))
            {
                Assert.Fail($"[Session {i}] Did not complete.");
            }

            Assert.IsTrue(counts.AliceCount > 0 || counts.BobCount > 0,
                $"No DH ratchet in session {i} (Alice: {counts.AliceCount}, Bob: {counts.BobCount})");
            WriteLine(
                $"[Session {i}] Passed: Alice DH Ratchets = {counts.AliceCount}, Bob DH Ratchets = {counts.BobCount}");
        }

        // Cleanup
        WriteLine("[Cleanup] Disposing all session pairs...");
        foreach (var (alice, bob, _, _) in sessionPairs)
        {
            try
            {
                await alice.DisposeAsync();
                await bob.DisposeAsync();
            }
            catch (Exception ex)
            {
                WriteLine($"[Cleanup] Error disposing session: {ex.Message}");
            }
        }

        WriteLine("[Test] SUCCESS - All sessions completed with DH ratchet rotations.");
    }


    [TestMethod]
    public async Task Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations_Succeeds()
    {
        WriteLine("[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] Running...");
        const int iterationCount = 506;
        uint aliceMessagesSent = 0;
        uint bobMessagesSent = 0;
        int aliceDhRatchets = 0;
        int bobDhRatchets = 0;

        for (int i = 1; i <= iterationCount; i++)
        {
            WriteLine($"\n--- Starting Iteration {i} ---");

            try
            {
                // Alice sends to Bob
                string aliceMessage = $"Message {i} from Alice to Bob (Overall #{aliceMessagesSent + 1})";
                byte[] alicePlaintextBytes = Encoding.UTF8.GetBytes(aliceMessage);
                WriteLine($"[Iteration {i}] Alice (Session {_aliceSessionId}) encrypting #{aliceMessagesSent + 1}...");
                CipherPayload alicePayload =
                    await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                        alicePlaintextBytes);
                bool aliceSentNewKey = !alicePayload.DhPublicKey.IsEmpty;
                if (aliceSentNewKey)
                {
                    aliceDhRatchets++;
                    WriteLine(
                        $"[Iteration {i}] Alice DH ratchet triggered, Index: {alicePayload.RatchetIndex}, DH Key: {Convert.ToHexString(alicePayload.DhPublicKey.ToByteArray())}");
                }

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
                if (bobSentNewKey)
                {
                    bobDhRatchets++;
                    WriteLine(
                        $"[Iteration {i}] Bob DH ratchet triggered, Index: {bobPayload.RatchetIndex}, DH Key: {Convert.ToHexString(bobPayload.DhPublicKey.ToByteArray())}");
                }

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
            catch (Exception ex)
            {
                WriteLine($"[Iteration {i}] Error: {ex.Message} ({ex.GetType().Name})");
                throw;
            }
        }

        Assert.AreEqual((uint)iterationCount, aliceMessagesSent, "Alice message count mismatch.");
        Assert.AreEqual((uint)iterationCount, bobMessagesSent, "Bob message count mismatch.");
        Assert.IsTrue(aliceDhRatchets > 0, "No DH ratchets triggered for Alice.");
        Assert.IsTrue(bobDhRatchets > 0, "No DH ratchets triggered for Bob.");
        WriteLine(
            $"\n[Test] SUCCESS - All {iterationCount} iterations completed without exceptions. Alice DH Ratchets: {aliceDhRatchets}, Bob DH Ratchets: {bobDhRatchets}");
    }
}