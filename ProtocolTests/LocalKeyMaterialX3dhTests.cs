using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography; // For AuthenticationTagMismatchException
using System.Text;
using System.Threading.Tasks;
using Ecliptix.Core.Protocol; // Your ShieldPro namespace
// For ShieldChainStepException if needed
using Ecliptix.Protobuf.CipherPayload; // Your CipherPayload namespace
using Ecliptix.Protobuf.PubKeyExchange; // Your PubKeyExchange namespace

// Assuming your test class setup initializes _aliceShieldPro, _bobShieldPro,
// _aliceSessionId, _bobSessionId, and _exchangeType correctly via [TestInitialize]

[TestClass]
public class ShieldProDoubleRatchetTests // Or your actual test class name
{
    private EcliptixProtocolSystem _aliceEcliptixProtocolSystem;
    private EcliptixProtocolSystem _bobEcliptixProtocolSystem;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private PubKeyExchangeType _exchangeType = PubKeyExchangeType.AppDeviceEphemeralConnect; // Example
    // --- End Fields ---

    public TestContext TestContext { get; set; }
    private void WriteLine(string message) => TestContext.WriteLine(message);

    // --- Your [TestInitialize] method goes here ---
    // Ensure it performs the handshake and sets the session IDs correctly
    [TestInitialize]
    public void InitializeAsync()
    {
        WriteLine("[TestInitialize] Setting up Alice and Bob...");
        // Create key materials (replace with your LocalKeyMaterial setup)
        var aliceMaterial = EcliptixSystemIdentityKeys.Create(1).Unwrap();
        var bobMaterial = EcliptixSystemIdentityKeys.Create(2).Unwrap();

        // Create ShieldPro instances
        _aliceEcliptixProtocolSystem = new EcliptixProtocolSystem(aliceMaterial);
        _bobEcliptixProtocolSystem = new EcliptixProtocolSystem(bobMaterial);

        uint connectId = 2;

        // Perform X3DH handshake
        WriteLine("[TestInitialize] Performing X3DH Handshake...");
        var aliceInitialMsg = _aliceEcliptixProtocolSystem.BeginDataCenterPubKeyExchange(connectId, _exchangeType);

        var bobResponseMsg =
            _bobEcliptixProtocolSystem.ProcessAndRespondToPubKeyExchange(connectId, aliceInitialMsg);

        _aliceEcliptixProtocolSystem.CompleteDataCenterPubKeyExchange(_aliceSessionId, _exchangeType,
            bobResponseMsg);

        WriteLine(
            $"[TestInitialize] Handshake Complete. Alice Session: {_aliceSessionId}, Bob Session: {_bobSessionId}");
    }

    [TestMethod]
    public void SingleSession_DHRatchet_TriggersAtInterval()
    {
        uint connectId = 2;
        var alice = new EcliptixProtocolSystem(EcliptixSystemIdentityKeys.Create(1).Unwrap());
        var bob = new EcliptixProtocolSystem(EcliptixSystemIdentityKeys.Create(2).Unwrap());
        var aliceMsg =
            alice.BeginDataCenterPubKeyExchange(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect);
        var bobMsg = bob.ProcessAndRespondToPubKeyExchange(connectId, aliceMsg);
        alice.CompleteDataCenterPubKeyExchange(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect,
            bobMsg);

        bool ratchetTriggered = false;
        for (int i = 1; i <= 10; i++)
        {
            var msg = Encoding.UTF8.GetBytes($"Msg {i}");
            var cipher =
                alice.ProduceOutboundMessage(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect, msg);
            if (!cipher.DhPublicKey.IsEmpty)
            {
                ratchetTriggered = true;
                WriteLine($"Ratchet triggered at message {i}");
            }

            bob.ProcessInboundMessage(connectId, PubKeyExchangeType.AppDeviceEphemeralConnect, cipher);
        }

        Assert.IsTrue(ratchetTriggered, "DH ratchet did not trigger at interval 10.");
    }

    [TestMethod]
    public async Task Ratchet_Parallel50Sessions_ConversationLike_Succeeds()
    {
        WriteLine("[Test: Ratchet_Parallel50Sessions_ConversationLike] Starting...");
        const int sessionCount = 50;
        const int messagesPerSession = 20;
        List<(EcliptixProtocolSystem Alice, EcliptixProtocolSystem Bob, uint AliceSessionId, uint BobSessionId)>
            sessionPairs =
                [];
        ConcurrentDictionary<uint, (uint AliceCount, uint BobCount)> dhRatchetCounts = new();

        // Setup
        WriteLine($"[Setup] Creating {sessionCount} session pairs...");
        for (int i = 0; i < sessionCount; i++)
        {
            uint testSessionId = (uint)i + 1;
            WriteLine($"[Setup] Initializing pair {testSessionId}...");

            try
            {
                var aliceMaterial = EcliptixSystemIdentityKeys.Create((uint)(i * 2 + 1)).Unwrap();
                var bobMaterial = EcliptixSystemIdentityKeys.Create((uint)(i * 2 + 2)).Unwrap();
                var alice = new EcliptixProtocolSystem(aliceMaterial);
                var bob = new EcliptixProtocolSystem(bobMaterial);

                var aliceInitialMsg =
                    alice.BeginDataCenterPubKeyExchange(testSessionId,
                        PubKeyExchangeType.AppDeviceEphemeralConnect);


                var bobResponseMsg = bob.ProcessAndRespondToPubKeyExchange(testSessionId, aliceInitialMsg);
                alice.CompleteDataCenterPubKeyExchange(testSessionId,
                    PubKeyExchangeType.AppDeviceEphemeralConnect, bobResponseMsg);

                WriteLine($"[Setup] Pair {testSessionId}: Alice Session {testSessionId}, Bob Session {testSessionId}");
                sessionPairs.Add((alice, bob, testSessionId, testSessionId));
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
            uint testSessionId = (uint)sessionPairs.IndexOf((alice, bob, aliceSessionId, bobSessionId)) + 1;
            tasks.Add(Task.Run(() =>
            {
                uint aliceDhRatchets = 0;
                uint bobDhRatchets = 0;

                WriteLine($"[Session {testSessionId}] Starting conversation...");
                for (uint j = 0; j < messagesPerSession; j++)
                {
                    var msgNumber = j + 1;
                    try
                    {
                        // Alice sends
                        var aliceMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Alice msg {msgNumber}");
                        WriteLine($"[Session {testSessionId}] Alice sending msg {msgNumber}...");
                        var aliceCipher =  alice.ProduceOutboundMessage(aliceSessionId,
                            PubKeyExchangeType.AppDeviceEphemeralConnect, aliceMsg);
                        WriteLine(
                            $"[Session {testSessionId}] Alice msg {msgNumber}: Index={aliceCipher.RatchetIndex}, DHKey={(aliceCipher.DhPublicKey.IsEmpty ? "None" : Convert.ToHexString(aliceCipher.DhPublicKey.ToByteArray()))}");
                        if (!aliceCipher.DhPublicKey.IsEmpty)
                        {
                            aliceDhRatchets++;
                            WriteLine(
                                $"[Session {testSessionId}] Alice DH ratchet at msg {msgNumber}, Index {aliceCipher.RatchetIndex}");
                        }

                        var bobPlaintext =  bob.ProcessInboundMessage(bobSessionId,
                            PubKeyExchangeType.AppDeviceEphemeralConnect, aliceCipher);
                        CollectionAssert.AreEqual(aliceMsg, bobPlaintext,
                            $"[Session {testSessionId}] Bob failed to decrypt Alice msg {msgNumber}");

                        // Bob sends
                        var bobMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Bob msg {msgNumber}");
                        WriteLine($"[Session {testSessionId}] Bob sending msg {msgNumber}...");
                        var bobCipher =  bob.ProduceOutboundMessage(bobSessionId,
                            PubKeyExchangeType.AppDeviceEphemeralConnect, bobMsg);
                        WriteLine(
                            $"[Session {testSessionId}] Bob msg {msgNumber}: Index={bobCipher.RatchetIndex}, DHKey={(bobCipher.DhPublicKey.IsEmpty ? "None" : Convert.ToHexString(bobCipher.DhPublicKey.ToByteArray()))}");
                        if (!bobCipher.DhPublicKey.IsEmpty)
                        {
                            bobDhRatchets++;
                            WriteLine(
                                $"[Session {testSessionId}] Bob DH ratchet at msg {msgNumber}, Index {bobCipher.RatchetIndex}");
                        }

                        var alicePlaintext =  alice.ProcessInboundMessage(aliceSessionId,
                            PubKeyExchangeType.AppDeviceEphemeralConnect, bobCipher);
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
        for (uint i = 1; i <= sessionCount; i++)
        {
            if (!dhRatchetCounts.TryGetValue(i, out (uint AliceCount, uint BobCount) counts))
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
            }
            catch (Exception ex)
            {
                WriteLine($"[Cleanup] Error disposing session: {ex.Message}");
            }
        }

        WriteLine("[Test] SUCCESS - All sessions completed with DH ratchet rotations.");
    }


    [TestMethod]
    public void Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations_Succeeds()
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
                     _aliceEcliptixProtocolSystem.ProduceOutboundMessage(_aliceSessionId, _exchangeType,
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
                     _bobEcliptixProtocolSystem.ProcessInboundMessage(_bobSessionId, _exchangeType,
                        alicePayload);
                CollectionAssert.AreEqual(alicePlaintextBytes, bobDecryptedBytes,
                    $"Bob decrypted Alice's message mismatch at iteration {i}");
                WriteLine($"[Iteration {i}] Bob successfully decrypted Alice's message {i}.");
                aliceMessagesSent++;

                // Bob sends to Alice
                string bobMessage = $"Response {i} from Bob to Alice (Overall #{bobMessagesSent + 1})";
                byte[] bobPlaintextBytes = Encoding.UTF8.GetBytes(bobMessage);
                WriteLine($"[Iteration {i}] Bob (Session {_bobSessionId}) encrypting #{bobMessagesSent + 1}...");
                CipherPayload bobPayload =
                     _bobEcliptixProtocolSystem.ProduceOutboundMessage(_bobSessionId, _exchangeType,
                        bobPlaintextBytes);
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
                     _aliceEcliptixProtocolSystem.ProcessInboundMessage(_aliceSessionId, _exchangeType,
                        bobPayload);
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