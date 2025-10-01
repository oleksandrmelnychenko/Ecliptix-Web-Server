using System.Collections.Concurrent;
using System.Text;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Domain.Protocol.Utilities;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Common;
using Google.Protobuf.WellKnownTypes;

[TestClass]
public class ShieldProDoubleRatchetTests
{
    private EcliptixProtocolSystem _aliceEcliptixProtocolSystem = null!;
    private EcliptixProtocolSystem _bobEcliptixProtocolSystem = null!;
    private const uint SessionId = 2;
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.DataCenterEphemeralConnect;

    public TestContext TestContext { get; set; }
    private void WriteLine(string message) => TestContext.WriteLine(message);

    [TestInitialize]
    public void Initialize()
    {
        WriteLine("[TestInitialize] Setting up Alice and Bob...");
        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> aliceMaterialResult = EcliptixSystemIdentityKeys.Create(1);
        if (aliceMaterialResult.IsErr) Assert.Fail($"Failed to create Alice keys: {aliceMaterialResult.UnwrapErr()}");

        Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> bobMaterialResult = EcliptixSystemIdentityKeys.Create(2);
        if (bobMaterialResult.IsErr) Assert.Fail($"Failed to create Bob keys: {bobMaterialResult.UnwrapErr()}");

        _aliceEcliptixProtocolSystem = new EcliptixProtocolSystem(aliceMaterialResult.Unwrap());
        _bobEcliptixProtocolSystem = new EcliptixProtocolSystem(bobMaterialResult.Unwrap());

        WriteLine("[TestInitialize] Performing X3DH Handshake...");
        Result<PubKeyExchange, EcliptixProtocolFailure> aliceInitialMsgResult =
            _aliceEcliptixProtocolSystem.BeginDataCenterPubKeyExchange(SessionId, _exchangeType);
        if (aliceInitialMsgResult.IsErr)
            Assert.Fail($"Alice failed to begin exchange: {aliceInitialMsgResult.UnwrapErr()}");
        PubKeyExchange aliceInitialMsg = aliceInitialMsgResult.Unwrap();

        Result<PubKeyExchange, EcliptixProtocolFailure> bobResponseMsgResult =
            _bobEcliptixProtocolSystem.ProcessAndRespondToPubKeyExchange(SessionId, aliceInitialMsg);
        if (bobResponseMsgResult.IsErr)
            Assert.Fail($"Bob failed to respond to exchange: {bobResponseMsgResult.UnwrapErr()}");
        PubKeyExchange bobResponseMsg = bobResponseMsgResult.Unwrap();

        Result<Unit, EcliptixProtocolFailure> aliceCompleteResult =
            _aliceEcliptixProtocolSystem.CompleteDataCenterPubKeyExchange(bobResponseMsg);
        if (aliceCompleteResult.IsErr)
            Assert.Fail($"Alice failed to complete exchange: {aliceCompleteResult.UnwrapErr()}");

        WriteLine($"[TestInitialize] Handshake Complete for Session ID: {SessionId}");
    }

    [TestMethod]
    public void SingleSession_DHRatchet_TriggersAtInterval()
    {
        bool ratchetTriggered = false;
        for (int i = 1; i <= 20; i++)
        {
            byte[] msg = Encoding.UTF8.GetBytes($"Msg {i}");

            Result<SecureEnvelope, EcliptixProtocolFailure> cipherResult = _aliceEcliptixProtocolSystem.ProduceOutboundMessage(msg);
            if (cipherResult.IsErr) Assert.Fail($"Alice failed to produce message {i}: {cipherResult.UnwrapErr()}");
            SecureEnvelope cipher = cipherResult.Unwrap();

            try
            {
                EnvelopeMetadata header = ProtocolMigrationHelper.ParseEnvelopeMetadata(cipher.MetaData).Unwrap();
                if (!header.DhPublicKey.IsEmpty)
                {
                    ratchetTriggered = true;
                    WriteLine($"Ratchet triggered at message {i}");
                }
            }
            catch (Exception ex)
            {
                Assert.Fail($"Failed to parse cipher header: {ex.Message}");
            }

            Result<byte[], EcliptixProtocolFailure> decryptResult = _bobEcliptixProtocolSystem.ProcessInboundMessage(cipher);
            if (decryptResult.IsErr) Assert.Fail($"Bob failed to process message {i}: {decryptResult.UnwrapErr()}");
        }

        Assert.IsTrue(ratchetTriggered, "DH ratchet did not trigger within 20 messages.");
    }

    [TestMethod]
    public async Task Ratchet_Parallel50Sessions_ConversationLike_Succeeds()
    {
        WriteLine("[Test: Ratchet_Parallel50Sessions_ConversationLike] Starting...");
        const int sessionCount = 50;
        const int messagesPerSession = 20;
        List<(EcliptixProtocolSystem Alice, EcliptixProtocolSystem Bob, uint SessionId)> sessionPairs = new List<(EcliptixProtocolSystem Alice, EcliptixProtocolSystem Bob, uint SessionId)>();
        ConcurrentDictionary<uint, (uint AliceCount, uint BobCount)> dhRatchetCounts = new ConcurrentDictionary<uint, (uint AliceCount, uint BobCount)>();

        WriteLine($"[Setup] Creating {sessionCount} session pairs...");
        for (uint i = 0; i < sessionCount; i++)
        {
            uint testSessionId = i + 100;
            WriteLine($"[Setup] Initializing pair for Session ID {testSessionId}...");

            Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> aliceMaterialResult = EcliptixSystemIdentityKeys.Create(i * 2 + 1);
            if (aliceMaterialResult.IsErr)
                Assert.Fail(
                    $"[Setup] Failed to create Alice keys for session {testSessionId}: {aliceMaterialResult.UnwrapErr()}");
            Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> bobMaterialResult = EcliptixSystemIdentityKeys.Create(i * 2 + 2);
            if (bobMaterialResult.IsErr)
                Assert.Fail(
                    $"[Setup] Failed to create Bob keys for session {testSessionId}: {bobMaterialResult.UnwrapErr()}");

            EcliptixProtocolSystem alice = new EcliptixProtocolSystem(aliceMaterialResult.Unwrap());
            EcliptixProtocolSystem bob = new EcliptixProtocolSystem(bobMaterialResult.Unwrap());

            Result<PubKeyExchange, EcliptixProtocolFailure> aliceInitialMsgResult = alice.BeginDataCenterPubKeyExchange(testSessionId, _exchangeType);
            if (aliceInitialMsgResult.IsErr)
                Assert.Fail(
                    $"[Setup] Alice failed handshake for session {testSessionId}: {aliceInitialMsgResult.UnwrapErr()}");

            Result<PubKeyExchange, EcliptixProtocolFailure> bobResponseMsgResult =
                bob.ProcessAndRespondToPubKeyExchange(testSessionId, aliceInitialMsgResult.Unwrap());
            if (bobResponseMsgResult.IsErr)
                Assert.Fail(
                    $"[Setup] Bob failed handshake for session {testSessionId}: {bobResponseMsgResult.UnwrapErr()}");

            Result<Unit, EcliptixProtocolFailure> aliceCompleteResult =
                alice.CompleteDataCenterPubKeyExchange(bobResponseMsgResult.Unwrap());
            if (aliceCompleteResult.IsErr)
                Assert.Fail(
                    $"[Setup] Alice failed to complete handshake for session {testSessionId}: {aliceCompleteResult.UnwrapErr()}");

            sessionPairs.Add((alice, bob, testSessionId));
        }

        WriteLine($"[Test] Running {sessionCount} conversations with {messagesPerSession} messages each...");
        List<Task> tasks = new List<Task>();
        foreach ((EcliptixProtocolSystem alice, EcliptixProtocolSystem bob, uint testSessionId) in sessionPairs)
        {
            tasks.Add(Task.Run(() =>
            {
                uint aliceDhRatchets = 0;
                uint bobDhRatchets = 0;

                for (uint j = 0; j < messagesPerSession; j++)
                {
                    byte[] aliceMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Alice msg {j + 1}");
                    Result<SecureEnvelope, EcliptixProtocolFailure> aliceCipherResult = alice.ProduceOutboundMessage(aliceMsg);
                    if (aliceCipherResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Alice failed to encrypt msg {j + 1}: {aliceCipherResult.UnwrapErr()}");
                    SecureEnvelope aliceCipher = aliceCipherResult.Unwrap();

                    try
                    {
                        EnvelopeMetadata aliceHeader = ProtocolMigrationHelper.ParseEnvelopeMetadata(aliceCipher.MetaData).Unwrap();
                        if (!aliceHeader.DhPublicKey.IsEmpty) aliceDhRatchets++;
                    }
                    catch (Exception ex)
                    {
                        Assert.Fail($"Failed to parse Alice cipher header: {ex.Message}");
                    }

                    Result<byte[], EcliptixProtocolFailure> bobPlaintextResult = bob.ProcessInboundMessage(aliceCipher);
                    if (bobPlaintextResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Bob failed to decrypt Alice msg {j + 1}: {bobPlaintextResult.UnwrapErr()}");
                    CollectionAssert.AreEqual(aliceMsg, bobPlaintextResult.Unwrap());

                    byte[] bobMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Bob msg {j + 1}");
                    Result<SecureEnvelope, EcliptixProtocolFailure> bobCipherResult = bob.ProduceOutboundMessage(bobMsg);
                    if (bobCipherResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Bob failed to encrypt msg {j + 1}: {bobCipherResult.UnwrapErr()}");
                    SecureEnvelope bobCipher = bobCipherResult.Unwrap();

                    try
                    {
                        EnvelopeMetadata bobHeader = ProtocolMigrationHelper.ParseEnvelopeMetadata(bobCipher.MetaData).Unwrap();
                        if (!bobHeader.DhPublicKey.IsEmpty) bobDhRatchets++;
                    }
                    catch (Exception ex)
                    {
                        Assert.Fail($"Failed to parse Bob cipher header: {ex.Message}");
                    }

                    Result<byte[], EcliptixProtocolFailure> alicePlaintextResult = alice.ProcessInboundMessage(bobCipher);
                    if (alicePlaintextResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Alice failed to decrypt Bob msg {j + 1}: {alicePlaintextResult.UnwrapErr()}");
                    CollectionAssert.AreEqual(bobMsg, alicePlaintextResult.Unwrap());
                }

                dhRatchetCounts[testSessionId] = (aliceDhRatchets, bobDhRatchets);
            }));
        }

        await Task.WhenAll(tasks);

        WriteLine("[Test] Verifying DH ratchet counts...");
        foreach ((EcliptixProtocolSystem _, EcliptixProtocolSystem _, uint testSessionId) in sessionPairs)
        {
            Assert.IsTrue(dhRatchetCounts.TryGetValue(testSessionId, out (uint AliceCount, uint BobCount) counts),
                $"[Session {testSessionId}] Did not complete.");
            Assert.IsTrue(counts.AliceCount > 0 && counts.BobCount > 0,
                $"DH ratchet did not occur for both parties in session {testSessionId}. Alice: {counts.AliceCount}, Bob: {counts.BobCount}");
        }

        WriteLine("[Test] SUCCESS - All sessions completed with DH ratchet rotations.");
    }

    [TestMethod]
    public void Ratchet_BidirectionalMessageExchange_Succeeds()
    {
        WriteLine("[Test: Ratchet_BidirectionalMessageExchange] Running...");
        const int iterationCount = 50;
        uint aliceDhRatchets = 0;
        uint bobDhRatchets = 0;

        for (int i = 1; i <= iterationCount; i++)
        {
            string aliceMessage = $"Message {i} from Alice";
            byte[] alicePlaintextBytes = Encoding.UTF8.GetBytes(aliceMessage);
            Result<SecureEnvelope, EcliptixProtocolFailure> alicePayloadResult = _aliceEcliptixProtocolSystem.ProduceOutboundMessage(alicePlaintextBytes);
            if (alicePayloadResult.IsErr)
                Assert.Fail($"[Iteration {i}] Alice failed to produce message: {alicePayloadResult.UnwrapErr()}");
            SecureEnvelope alicePayload = alicePayloadResult.Unwrap();

            try
            {
                EnvelopeMetadata aliceHeader = ProtocolMigrationHelper.ParseEnvelopeMetadata(alicePayload.MetaData).Unwrap();
                if (!aliceHeader.DhPublicKey.IsEmpty) aliceDhRatchets++;
            }
            catch (Exception ex)
            {
                Assert.Fail($"Failed to parse Alice cipher header: {ex.Message}");
            }

            Result<byte[], EcliptixProtocolFailure> bobDecryptedResult = _bobEcliptixProtocolSystem.ProcessInboundMessage(alicePayload);
            if (bobDecryptedResult.IsErr)
                Assert.Fail($"[Iteration {i}] Bob failed to decrypt Alice's message: {bobDecryptedResult.UnwrapErr()}");
            CollectionAssert.AreEqual(alicePlaintextBytes, bobDecryptedResult.Unwrap());

            string bobMessage = $"Response {i} from Bob";
            byte[] bobPlaintextBytes = Encoding.UTF8.GetBytes(bobMessage);
            Result<SecureEnvelope, EcliptixProtocolFailure> bobPayloadResult = _bobEcliptixProtocolSystem.ProduceOutboundMessage(bobPlaintextBytes);
            if (bobPayloadResult.IsErr)
                Assert.Fail($"[Iteration {i}] Bob failed to produce response: {bobPayloadResult.UnwrapErr()}");
            SecureEnvelope bobPayload = bobPayloadResult.Unwrap();

            try
            {
                EnvelopeMetadata bobHeader = ProtocolMigrationHelper.ParseEnvelopeMetadata(bobPayload.MetaData).Unwrap();
                if (!bobHeader.DhPublicKey.IsEmpty) bobDhRatchets++;
            }
            catch (Exception ex)
            {
                Assert.Fail($"Failed to parse Bob cipher header: {ex.Message}");
            }

            Result<byte[], EcliptixProtocolFailure> aliceDecryptedResult = _aliceEcliptixProtocolSystem.ProcessInboundMessage(bobPayload);
            if (aliceDecryptedResult.IsErr)
                Assert.Fail(
                    $"[Iteration {i}] Alice failed to decrypt Bob's response: {aliceDecryptedResult.UnwrapErr()}");
            CollectionAssert.AreEqual(bobPlaintextBytes, aliceDecryptedResult.Unwrap());
        }

        Assert.IsTrue(aliceDhRatchets > 0, "No DH ratchets triggered for Alice.");
        Assert.IsTrue(bobDhRatchets > 0, "No DH ratchets triggered for Bob.");
        WriteLine(
            $"[Test] SUCCESS - All {iterationCount} iterations completed. Alice DH Ratchets: {aliceDhRatchets}, Bob DH Ratchets: {bobDhRatchets}");
    }
}