using System.Collections.Concurrent;
using System.Text;
using Ecliptix.Core.Protocol;
using Ecliptix.Protobuf.Protocol;
using Ecliptix.Core.Domain.Protocol;

[TestClass]
public class ShieldProDoubleRatchetTests
{
    private EcliptixProtocolSystem _aliceEcliptixProtocolSystem = null!;
    private EcliptixProtocolSystem _bobEcliptixProtocolSystem = null!;
    private const uint SessionId = 2; // Using a constant session ID for simplicity in these tests
    private readonly PubKeyExchangeType _exchangeType = PubKeyExchangeType.DataCenterEphemeralConnect;

    public TestContext TestContext { get; set; }
    private void WriteLine(string message) => TestContext.WriteLine(message);

    [TestInitialize]
    public void Initialize()
    {
        WriteLine("[TestInitialize] Setting up Alice and Bob...");
        var aliceMaterialResult = EcliptixSystemIdentityKeys.Create(1);
        if (aliceMaterialResult.IsErr) Assert.Fail($"Failed to create Alice keys: {aliceMaterialResult.UnwrapErr()}");

        var bobMaterialResult = EcliptixSystemIdentityKeys.Create(2);
        if (bobMaterialResult.IsErr) Assert.Fail($"Failed to create Bob keys: {bobMaterialResult.UnwrapErr()}");

        _aliceEcliptixProtocolSystem = new EcliptixProtocolSystem(aliceMaterialResult.Unwrap());
        _bobEcliptixProtocolSystem = new EcliptixProtocolSystem(bobMaterialResult.Unwrap());

        WriteLine("[TestInitialize] Performing X3DH Handshake...");
        var aliceInitialMsgResult =
            _aliceEcliptixProtocolSystem.BeginDataCenterPubKeyExchange(SessionId, _exchangeType);
        if (aliceInitialMsgResult.IsErr)
            Assert.Fail($"Alice failed to begin exchange: {aliceInitialMsgResult.UnwrapErr()}");
        var aliceInitialMsg = aliceInitialMsgResult.Unwrap();

        var bobResponseMsgResult =
            _bobEcliptixProtocolSystem.ProcessAndRespondToPubKeyExchange(SessionId, aliceInitialMsg);
        if (bobResponseMsgResult.IsErr)
            Assert.Fail($"Bob failed to respond to exchange: {bobResponseMsgResult.UnwrapErr()}");
        var bobResponseMsg = bobResponseMsgResult.Unwrap();

        var aliceCompleteResult =
            _aliceEcliptixProtocolSystem.CompleteDataCenterPubKeyExchange(bobResponseMsg);
        if (aliceCompleteResult.IsErr)
            Assert.Fail($"Alice failed to complete exchange: {aliceCompleteResult.UnwrapErr()}");

        WriteLine($"[TestInitialize] Handshake Complete for Session ID: {SessionId}");
    }

    [TestMethod]
    public void SingleSession_DHRatchet_TriggersAtInterval()
    {
        bool ratchetTriggered = false;
        for (int i = 1; i <= 20; i++) // Increased iterations to guarantee a trigger
        {
            var msg = Encoding.UTF8.GetBytes($"Msg {i}");

            var cipherResult = _aliceEcliptixProtocolSystem.ProduceOutboundMessage(msg);
            if (cipherResult.IsErr) Assert.Fail($"Alice failed to produce message {i}: {cipherResult.UnwrapErr()}");
            var cipher = cipherResult.Unwrap();

            if (!cipher.DhPublicKey.IsEmpty)
            {
                ratchetTriggered = true;
                WriteLine($"Ratchet triggered at message {i}");
            }

            var decryptResult = _bobEcliptixProtocolSystem.ProcessInboundMessage(cipher);
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
        var sessionPairs = new List<(EcliptixProtocolSystem Alice, EcliptixProtocolSystem Bob, uint SessionId)>();
        var dhRatchetCounts = new ConcurrentDictionary<uint, (uint AliceCount, uint BobCount)>();

        WriteLine($"[Setup] Creating {sessionCount} session pairs...");
        for (uint i = 0; i < sessionCount; i++)
        {
            uint testSessionId = i + 100; // Use unique IDs
            WriteLine($"[Setup] Initializing pair for Session ID {testSessionId}...");

            var aliceMaterialResult = EcliptixSystemIdentityKeys.Create(i * 2 + 1);
            if (aliceMaterialResult.IsErr)
                Assert.Fail(
                    $"[Setup] Failed to create Alice keys for session {testSessionId}: {aliceMaterialResult.UnwrapErr()}");
            var bobMaterialResult = EcliptixSystemIdentityKeys.Create(i * 2 + 2);
            if (bobMaterialResult.IsErr)
                Assert.Fail(
                    $"[Setup] Failed to create Bob keys for session {testSessionId}: {bobMaterialResult.UnwrapErr()}");

            var alice = new EcliptixProtocolSystem(aliceMaterialResult.Unwrap());
            var bob = new EcliptixProtocolSystem(bobMaterialResult.Unwrap());

            var aliceInitialMsgResult = alice.BeginDataCenterPubKeyExchange(testSessionId, _exchangeType);
            if (aliceInitialMsgResult.IsErr)
                Assert.Fail(
                    $"[Setup] Alice failed handshake for session {testSessionId}: {aliceInitialMsgResult.UnwrapErr()}");

            var bobResponseMsgResult =
                bob.ProcessAndRespondToPubKeyExchange(testSessionId, aliceInitialMsgResult.Unwrap());
            if (bobResponseMsgResult.IsErr)
                Assert.Fail(
                    $"[Setup] Bob failed handshake for session {testSessionId}: {bobResponseMsgResult.UnwrapErr()}");

            var aliceCompleteResult =
                alice.CompleteDataCenterPubKeyExchange(bobResponseMsgResult.Unwrap());
            if (aliceCompleteResult.IsErr)
                Assert.Fail(
                    $"[Setup] Alice failed to complete handshake for session {testSessionId}: {aliceCompleteResult.UnwrapErr()}");

            sessionPairs.Add((alice, bob, testSessionId));
        }

        WriteLine($"[Test] Running {sessionCount} conversations with {messagesPerSession} messages each...");
        var tasks = new List<Task>();
        foreach (var (alice, bob, testSessionId) in sessionPairs)
        {
            tasks.Add(Task.Run(() =>
            {
                uint aliceDhRatchets = 0;
                uint bobDhRatchets = 0;

                for (uint j = 0; j < messagesPerSession; j++)
                {
                    // Alice sends
                    var aliceMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Alice msg {j + 1}");
                    var aliceCipherResult = alice.ProduceOutboundMessage(aliceMsg);
                    if (aliceCipherResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Alice failed to encrypt msg {j + 1}: {aliceCipherResult.UnwrapErr()}");
                    var aliceCipher = aliceCipherResult.Unwrap();

                    if (!aliceCipher.DhPublicKey.IsEmpty) aliceDhRatchets++;

                    var bobPlaintextResult = bob.ProcessInboundMessage(aliceCipher);
                    if (bobPlaintextResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Bob failed to decrypt Alice msg {j + 1}: {bobPlaintextResult.UnwrapErr()}");
                    CollectionAssert.AreEqual(aliceMsg, bobPlaintextResult.Unwrap());

                    // Bob sends
                    var bobMsg = Encoding.UTF8.GetBytes($"Session {testSessionId}: Bob msg {j + 1}");
                    var bobCipherResult = bob.ProduceOutboundMessage(bobMsg);
                    if (bobCipherResult.IsErr)
                        throw new AssertFailedException(
                            $"[Session {testSessionId}] Bob failed to encrypt msg {j + 1}: {bobCipherResult.UnwrapErr()}");
                    var bobCipher = bobCipherResult.Unwrap();

                    if (!bobCipher.DhPublicKey.IsEmpty) bobDhRatchets++;

                    var alicePlaintextResult = alice.ProcessInboundMessage(bobCipher);
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
        foreach (var (_, _, testSessionId) in sessionPairs)
        {
            Assert.IsTrue(dhRatchetCounts.TryGetValue(testSessionId, out var counts),
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
        const int iterationCount = 50; // A reasonable number for a single test
        uint aliceDhRatchets = 0;
        uint bobDhRatchets = 0;

        for (int i = 1; i <= iterationCount; i++)
        {
            // Alice sends to Bob
            string aliceMessage = $"Message {i} from Alice";
            byte[] alicePlaintextBytes = Encoding.UTF8.GetBytes(aliceMessage);
            var alicePayloadResult = _aliceEcliptixProtocolSystem.ProduceOutboundMessage(alicePlaintextBytes);
            if (alicePayloadResult.IsErr)
                Assert.Fail($"[Iteration {i}] Alice failed to produce message: {alicePayloadResult.UnwrapErr()}");
            var alicePayload = alicePayloadResult.Unwrap();

            if (!alicePayload.DhPublicKey.IsEmpty) aliceDhRatchets++;

            var bobDecryptedResult = _bobEcliptixProtocolSystem.ProcessInboundMessage(alicePayload);
            if (bobDecryptedResult.IsErr)
                Assert.Fail($"[Iteration {i}] Bob failed to decrypt Alice's message: {bobDecryptedResult.UnwrapErr()}");
            CollectionAssert.AreEqual(alicePlaintextBytes, bobDecryptedResult.Unwrap());

            // Bob sends to Alice
            string bobMessage = $"Response {i} from Bob";
            byte[] bobPlaintextBytes = Encoding.UTF8.GetBytes(bobMessage);
            var bobPayloadResult = _bobEcliptixProtocolSystem.ProduceOutboundMessage(bobPlaintextBytes);
            if (bobPayloadResult.IsErr)
                Assert.Fail($"[Iteration {i}] Bob failed to produce response: {bobPayloadResult.UnwrapErr()}");
            var bobPayload = bobPayloadResult.Unwrap();

            if (!bobPayload.DhPublicKey.IsEmpty) bobDhRatchets++;

            var aliceDecryptedResult = _aliceEcliptixProtocolSystem.ProcessInboundMessage(bobPayload);
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