using Microsoft.VisualStudio.TestTools.UnitTesting; // Assuming MSTest
using System;
using System.Security.Cryptography; // For AuthenticationTagMismatchException
using System.Text;
using System.Threading.Tasks;
using Ecliptix.Core.Protocol; // Your ShieldPro namespace
using Ecliptix.Protobuf.CipherPayload; // Your CipherPayload namespace
using Ecliptix.Protobuf.PubKeyExchange; // Your PubKeyExchange namespace

// Assuming your test class setup initializes _aliceShieldPro, _bobShieldPro,
// _aliceSessionId, _bobSessionId, and _exchangeType correctly via [TestInitialize]

[TestClass]
public class ShieldProDoubleRatchetTests // Or your actual test class name
{
    // Your [TestInitialize] and fields (_aliceShieldPro, _bobShieldPro, etc.) go here

    // Example placeholder - replace with your actual setup
    private ShieldPro _aliceShieldPro;
    private ShieldPro _bobShieldPro;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private PubKeyExchangeOfType _exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect; // Example

    public TestContext TestContext { get; set; } // To use WriteLine

    private void WriteLine(string message) => TestContext.WriteLine(message);

    [TestInitialize]
    public async Task InitializeAsync()
    {
        // --- Replace with your ACTUAL Initialization Logic ---
        WriteLine("[TestInitialize] Setting up Alice and Bob...");

        // Create key materials (replace with your LocalKeyMaterial setup)
        var aliceMaterial = new LocalKeyMaterial(3);
        var bobMaterial = new LocalKeyMaterial(3);

        // Create ShieldPro instances
        _aliceShieldPro = new ShieldPro(aliceMaterial);
        _bobShieldPro = new ShieldPro(bobMaterial);

        // Perform X3DH handshake
        WriteLine("[TestInitialize] Performing X3DH Handshake...");
        var (aliceSessionId, aliceInitialMsg) = await _aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(_exchangeType);
        _aliceSessionId = aliceSessionId;

        var (bobSessionId, bobResponseMsg) = await _bobShieldPro.ProcessAndRespondToPubKeyExchangeAsync(aliceInitialMsg);
        _bobSessionId = bobSessionId;

        await _aliceShieldPro.CompletePubKeyExchangeAsync(_aliceSessionId, _exchangeType, bobResponseMsg);

        WriteLine($"[TestInitialize] Handshake Complete. Alice Session: {_aliceSessionId}, Bob Session: {_bobSessionId}");
        // --- End of Placeholder Initialization ---
    }

     [TestCleanup]
    public async Task CleanupAsync()
    {
        WriteLine("[Cleanup] Disposing test resources...");
        if (_aliceShieldPro != null) await _aliceShieldPro.DisposeAsync();
        if (_bobShieldPro != null) await _bobShieldPro.DisposeAsync();
         WriteLine("[Cleanup] Test resources disposed.");
    }


    [TestMethod]
    public async Task Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations_Succeeds()
    {
        WriteLine("[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] Running...");
        const int iterationCount = 153;
        const uint DhRotationInterval = 50; // Must match the interval in ShieldSession

        uint aliceMessagesSent = 0;
        uint bobMessagesSent = 0;
        uint expectedAliceIndex = 0;
        uint expectedBobIndex = 0;

        for (int i = 1; i <= iterationCount; i++)
        {
            WriteLine($"\n--- Starting Iteration {i} ---");

            //---------------------------------
            // Alice sends to Bob
            //---------------------------------
            string aliceMessage = $"Message {i} from Alice to Bob (Overall #{aliceMessagesSent + 1})";
            byte[] alicePlaintextBytes = Encoding.UTF8.GetBytes(aliceMessage);
            WriteLine($"[Iteration {i}] Alice (Session {_aliceSessionId}) encrypting #{aliceMessagesSent + 1}...");

            CipherPayload alicePayload =
                await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, alicePlaintextBytes);
            bool aliceSentNewKey = !alicePayload.DhPublicKey.IsEmpty; // Did Alice include a new key?

            // --- Alice Index Check ---
            expectedAliceIndex++;
            if (aliceSentNewKey) // Alice's index resets AFTER sending the key
            {
                 WriteLine($"[Iteration {i}] Alice performed DH ratchet, resetting expected index.");
                expectedAliceIndex = 1;
            }
            WriteLine(
                $"[Iteration {i}] Alice Payload Details - Index: {alicePayload.RatchetIndex}, DH Key Sent: {aliceSentNewKey}, Expected Index: {expectedAliceIndex}");
            Assert.AreEqual(expectedAliceIndex, alicePayload.RatchetIndex,
                $"Alice index mismatch at message #{aliceMessagesSent + 1}. Expected: {expectedAliceIndex}");

            //---------------------------------
            // Bob Receives from Alice
            //---------------------------------
            WriteLine(
                $"[Iteration {i}] Bob (Session {_bobSessionId}) decrypting Alice's message {i} (Payload Index {alicePayload.RatchetIndex}, Alice Sent Key: {aliceSentNewKey})...");
            bool bobDecryptionExpectedToFail = aliceSentNewKey; // Bob cannot decrypt immediately if Alice sent a key

            try
            {
                byte[] bobDecryptedBytes =
                    await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, alicePayload);

                // If we expected failure but got success, it's an error
                if (bobDecryptionExpectedToFail)
                {
                    Assert.Fail($"Bob decryption SUCCEEDED unexpectedly at iteration {i} after Alice sent a new DH key.");
                }

                // Otherwise, assert content equality
                CollectionAssert.AreEqual(alicePlaintextBytes, bobDecryptedBytes,
                    $"Bob decrypted Alice's message mismatch at iteration {i}");
                WriteLine($"[Iteration {i}] Bob successfully decrypted Alice's message {i}.");
            }
            catch (Ecliptix.Core.Protocol.ShieldChainStepException ex) when (ex.InnerException is System.Security.Cryptography.AuthenticationTagMismatchException)
            {
                // Decryption failed. Check if it was expected.
                if (bobDecryptionExpectedToFail)
                {
                    WriteLine($"[Iteration {i}] Bob decryption failed AUTHENTICATION as expected after receiving Alice's new DH key.");
                    // This is the correct behavior, continue the test.
                }
                else
                {
                    // Decryption failed unexpectedly. Re-throw to fail the test.
                    WriteLine($"[Iteration {i}] Bob decryption failed unexpectedly: {ex}");
                    throw;
                }
            }
            // Let any other unexpected exceptions propagate and fail the test.

            aliceMessagesSent++;


            //---------------------------------
            // Bob sends to Alice
            //---------------------------------
            string bobMessage = $"Response {i} from Bob to Alice (Overall #{bobMessagesSent + 1})";
            byte[] bobPlaintextBytes = Encoding.UTF8.GetBytes(bobMessage);
            WriteLine($"[Iteration {i}] Bob (Session {_bobSessionId}) encrypting #{bobMessagesSent + 1}...");

            CipherPayload bobPayload =
                await _bobShieldPro.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType, bobPlaintextBytes);
            bool bobSentNewKey = !bobPayload.DhPublicKey.IsEmpty; // Did Bob include a new key?

            // --- Bob Index Check ---
            expectedBobIndex++;
            if (bobSentNewKey) // Bob's index resets AFTER sending the key
            {
                 WriteLine($"[Iteration {i}] Bob performed DH ratchet, resetting expected index.");
                expectedBobIndex = 1;
            }
            WriteLine(
                $"[Iteration {i}] Bob Payload Details - Index: {bobPayload.RatchetIndex}, DH Key Sent: {bobSentNewKey}, Expected Index: {expectedBobIndex}");
            Assert.AreEqual(expectedBobIndex, bobPayload.RatchetIndex,
                $"Bob index mismatch at message #{bobMessagesSent + 1}. Expected: {expectedBobIndex}");


            //---------------------------------
            // Alice Receives from Bob
            //---------------------------------
            WriteLine(
                $"[Iteration {i}] Alice (Session {_aliceSessionId}) decrypting Bob's response {i} (Payload Index {bobPayload.RatchetIndex}, Bob Sent Key: {bobSentNewKey})...");
            bool aliceDecryptionExpectedToFail = bobSentNewKey; // Alice cannot decrypt immediately if Bob sent a key

            try
            {
                byte[] aliceDecryptedBytes =
                    await _aliceShieldPro.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType, bobPayload);

                 // If we expected failure but got success, it's an error
                if (aliceDecryptionExpectedToFail)
                {
                    Assert.Fail($"Alice decryption SUCCEEDED unexpectedly at iteration {i} after Bob sent a new DH key.");
                }

                // Otherwise, assert content equality
                CollectionAssert.AreEqual(bobPlaintextBytes, aliceDecryptedBytes,
                    $"Alice decrypted Bob's response mismatch at iteration {i}");
                WriteLine($"[Iteration {i}] Alice successfully decrypted Bob's response {i}.");
            }
            catch (Ecliptix.Core.Protocol.ShieldChainStepException ex) when (ex.InnerException is System.Security.Cryptography.AuthenticationTagMismatchException)
            {
                 // Decryption failed. Check if it was expected.
                if (aliceDecryptionExpectedToFail)
                {
                     WriteLine($"[Iteration {i}] Alice decryption failed AUTHENTICATION as expected after receiving Bob's new DH key.");
                     // This is the correct behavior, continue the test.
                }
                else
                {
                    // Decryption failed unexpectedly. Re-throw to fail the test.
                     WriteLine($"[Iteration {i}] Alice decryption failed unexpectedly: {ex}");
                    throw;
                }
            }
             // Let any other unexpected exceptions propagate and fail the test.

            bobMessagesSent++;

            WriteLine($"[Iteration {i}] Bidirectional exchange completed.");
        }

        Assert.AreEqual((uint)iterationCount, aliceMessagesSent, "Alice message count mismatch.");
        Assert.AreEqual((uint)iterationCount, bobMessagesSent, "Bob message count mismatch.");
        WriteLine(
            $"\n[Test: Ratchet_BidirectionalMessageExchange_153Iterations_WithMultipleDHRotations] SUCCESS - All {iterationCount} iterations completed (allowing for expected post-ratchet decryption failures).");
    }
}