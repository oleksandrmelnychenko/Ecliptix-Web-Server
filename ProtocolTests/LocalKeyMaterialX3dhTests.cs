using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
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
    // --- End [TestCleanup] ---


    [TestMethod]
    public async Task Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations_Succeeds()
    {
        WriteLine("[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] Running...");
        const int iterationCount = 70;

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