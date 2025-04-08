using Xunit.Abstractions;
using System.Text;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.CipherPayload;
using Google.Protobuf;

namespace ShieldProTests;

// Renamed class to focus on Double Ratchet tests
public class ShieldProDoubleRatchetTests(ITestOutputHelper _output) : IAsyncDisposable, IAsyncLifetime
{
    private LocalKeyMaterial _aliceKeys = null!;
    private LocalKeyMaterial _bobKeys = null!;
    private ShieldSessionManager _aliceSessionManager = null!;
    private ShieldSessionManager _bobSessionManager = null!;
    private ShieldPro _aliceShieldPro = null!;
    private ShieldPro _bobShieldPro = null!;

    private uint _aliceSessionId;
    private uint _bobSessionId;
    private PubKeyExchangeOfType _exchangeType;

    // Static init for Sodium
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

    // Instances are created in InitializeAsync

    private static bool CompareSecureHandles(SodiumSecureMemoryHandle? handleA, SodiumSecureMemoryHandle? handleB)
    {
        if (ReferenceEquals(handleA, handleB)) return true;
        if (handleA == null || handleB == null) return false;
        if (handleA.IsInvalid || handleB.IsInvalid || handleA.Length != handleB.Length ||
            handleA.Length == 0) return false;

        if (handleA.Length > 1024)
        {
            byte[] bytesAHeap = new byte[handleA.Length];
            byte[] bytesBHeap = new byte[handleB.Length];
            try
            {
                handleA.Read(bytesAHeap);
                handleB.Read(bytesBHeap);
                return bytesAHeap.SequenceEqual(bytesBHeap);
            }
            finally
            {
                SodiumInterop.SecureWipe(bytesAHeap);
                SodiumInterop.SecureWipe(bytesBHeap);
            }
        }

        Span<byte> bytesA = stackalloc byte[handleA.Length];
        Span<byte> bytesB = stackalloc byte[handleB.Length];
        bool equal;

        try
        {
            handleA.Read(bytesA);
            handleB.Read(bytesB);
            equal = bytesA.SequenceEqual(bytesB);
        }
        catch (ObjectDisposedException odex)
        {
            Console.WriteLine($"[CompareSecureHandles] Error: Read disposed handle. {odex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CompareSecureHandles] Unexpected error: {ex.Message}");
            return false;
        }
        finally
        {
            bytesA.Clear();
            bytesB.Clear();
        }

        return equal;
    }

    // Inside ShieldProDoubleRatchetTests class

    // --- Test Setup Helper (IAsyncLifetime) ---
    // Performs handshake simulating steps more explicitly
    public async Task InitializeAsync()
    {
        _output.WriteLine("[SETUP DR V2] Initializing keys and managers...");
        _aliceKeys = new LocalKeyMaterial(5);
        _bobKeys = new LocalKeyMaterial(5);
        _aliceSessionManager = ShieldSessionManager.CreateWithCleanupTask();
        _bobSessionManager = ShieldSessionManager.CreateWithCleanupTask();
        _aliceShieldPro = new ShieldPro(_aliceKeys, _aliceSessionManager);
        _bobShieldPro = new ShieldPro(_bobKeys, _bobSessionManager);
        _exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect; // Use actual enum value

        _output.WriteLine("[SETUP DR V2] Performing simulated X3DH Handshake (granular)...");

        SodiumSecureMemoryHandle? aliceRootKeyHandle = null;
        SodiumSecureMemoryHandle? bobRootKeyHandle = null;
        Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle? alicePublicBundleProto = null;
        Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle? bobPublicBundleProto = null;

        try
        {
            // --- Preparations ---
            // 1. Bob "publishes" his bundle (Protobuf type)
            bobPublicBundleProto = _bobKeys.CreatePublicBundle().ToProtobufExchange();
            if (bobPublicBundleProto == null) throw new InvalidOperationException("Bob failed create bundle");

            // 2. Alice generates her ephemeral key (secret stored in _aliceKeys)
            _aliceKeys.GenerateEphemeralKeyPair();
            // Alice creates her public bundle (Protobuf type)
            alicePublicBundleProto = _aliceKeys.CreatePublicBundle().ToProtobufExchange();
            if (alicePublicBundleProto == null) throw new InvalidOperationException("Alice failed create bundle");


            // --- Alice's Side (Initiator) ---
            _output.WriteLine("[SETUP DR V2] Alice processing...");
            // 3. Alice creates her session state locally BEFORE calculating secret
            _aliceSessionId = Helpers.GenerateRandomUInt32(true);
            var aliceSession =
                new ShieldSession(_aliceSessionId, alicePublicBundleProto); // Pass Alice's own PROTO bundle
            _aliceSessionManager.InsertSessionOrThrow(_aliceSessionId, _exchangeType, aliceSession);

            // 4. Alice converts Bob's bundle to internal format for derivation
            var bobBundleInternalResult = LocalPublicKeyBundle.FromProtobufExchange(bobPublicBundleProto);
            Assert.True(bobBundleInternalResult.IsOk,
                bobBundleInternalResult.IsErr
                    ? $"Failed parsing Bob's bundle: {bobBundleInternalResult.UnwrapErr()}"
                    : "Failed parsing Bob's bundle");
            var bobBundleInternal = bobBundleInternalResult.Unwrap();

            // 5. Alice derives the root key (uses internal ephemeral key)
            var aliceDeriveResult = _aliceKeys.X3dhDeriveSharedSecret(bobBundleInternal, ShieldPro.X3dhInfo);
            Assert.True(aliceDeriveResult.IsOk,
                aliceDeriveResult.IsErr
                    ? $"Alice derivation failed: {aliceDeriveResult.UnwrapErr()}"
                    : "Alice derivation failed");
            aliceRootKeyHandle = aliceDeriveResult.Unwrap(); // Keep for comparison & finalizing

            // 6. Alice finalizes her session state (sets peer bundle, derives chains, sets state)
            // We need to acquire the lock for Alice's session to finalize it
            var aliceHolder = _aliceSessionManager.GetSessionHolderOrThrow(_aliceSessionId, _exchangeType);
            await aliceHolder.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (aliceHolder.Session.State != PubKeyExchangeState.Init)
                    throw new InvalidOperationException("Alice session not Init before finalize.");
                aliceHolder.Session.SetPeerBundle(bobPublicBundleProto); // Set Bob's PROTO bundle

                Span<byte> rootKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> senderKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> receiverKeyBytes = stackalloc byte[Constants.X25519KeySize];
                try
                {
                    aliceRootKeyHandle.Read(rootKeyBytes);
                    using (var hkdfSender = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfSender.Expand(ShieldPro.SenderChainInfo, senderKeyBytes);
                    }

                    using (var hkdfReceiver = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfReceiver.Expand(ShieldPro.ReceiverChainInfo, receiverKeyBytes);
                    }

                    // Pass spans to FinalizeChainKey
                    aliceHolder.Session.FinalizeChainKey(senderKeyBytes.ToArray(), receiverKeyBytes.ToArray());
                }
                finally
                {
                    rootKeyBytes.Clear();
                    senderKeyBytes.Clear();
                    receiverKeyBytes.Clear();
                }

                aliceHolder.Session.SetConnectionState(PubKeyExchangeState.Complete);
                _output.WriteLine($"[SETUP DR V2] Alice session {_aliceSessionId} finalized.");
            }
            finally
            {
                aliceHolder.Lock.Release();
            }


            // --- Bob's Side (Responder) ---
            _output.WriteLine("[SETUP DR V2] Bob processing...");
            // 7. Bob creates his session state locally upon receiving Alice's first message simulation
            _bobSessionId = Helpers.GenerateRandomUInt32(true);
            // Bob needs his OWN bundle for his session state
            var bobLocalBundleProto = _bobKeys.CreatePublicBundle().ToProtobufExchange(); // Re-create or use the one from step 1
            if (bobLocalBundleProto == null)
                throw new InvalidOperationException("Bob failed create bundle for session");
            var bobSession = new ShieldSession(_bobSessionId, bobLocalBundleProto);
            _bobSessionManager.InsertSessionOrThrow(_bobSessionId, _exchangeType, bobSession);

            // 8. Bob converts Alice's bundle to internal format if needed for Verify SPK (though not strictly needed for CalculateSharedSecretAsRecipient)
            // Let's assume verification happened before this point or isn't needed for this specific setup test.
            // var aliceBundleInternalResult = LocalPublicKeyBundle.FromProtobufExchange(alicePublicBundleProto);
            // Assert.True(aliceBundleInternalResult.IsOk);
            // var aliceBundleInternal = aliceBundleInternalResult.Unwrap();
            // // Bob would verify Alice's SPK signature here if Alice had one (X3DH doesn't require Alice SPK sig check by Bob)


            // 9. Bob calculates the shared secret using HIS keys and ALICE's public keys
            uint? opkIdUsedByAlice = bobBundleInternal.OneTimePreKeys.FirstOrDefault()?.PreKeyId; // Get ID Alice used

            var bobDeriveResult = _bobKeys.CalculateSharedSecretAsRecipient(
                alicePublicBundleProto.IdentityX25519PublicKey.ToByteArray(), // Alice's IKa_pub from HER proto bundle
                alicePublicBundleProto.EphemeralX25519PublicKey.ToByteArray(), // Alice's Ea_pub from HER proto bundle
                opkIdUsedByAlice, // ID of Bob's OPK that Alice chose
                ShieldPro.X3dhInfo // Use same info string
            );
            Assert.True(bobDeriveResult.IsOk,
                bobDeriveResult.IsErr
                    ? $"Bob derivation failed: {bobDeriveResult.UnwrapErr()}"
                    : "Bob derivation failed");
            bobRootKeyHandle = bobDeriveResult.Unwrap(); // Keep for comparison & finalizing

            // 10. Bob finalizes his session state
            var bobHolder = _bobSessionManager.GetSessionHolderOrThrow(_bobSessionId, _exchangeType);
            await bobHolder.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (bobHolder.Session.State != PubKeyExchangeState.Init)
                    throw new InvalidOperationException("Bob session not Init before finalize.");
                bobHolder.Session.SetPeerBundle(alicePublicBundleProto); // Set Alice's PROTO bundle

                Span<byte> rootKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> senderKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> receiverKeyBytes = stackalloc byte[Constants.X25519KeySize];
                try
                {
                    bobRootKeyHandle.Read(rootKeyBytes); // Use Bob's derived root key
                    using (var hkdfSender = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfSender.Expand(ShieldPro.SenderChainInfo, senderKeyBytes);
                    }

                    using (var hkdfReceiver = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfReceiver.Expand(ShieldPro.ReceiverChainInfo, receiverKeyBytes);
                    }

                    // Pass spans to FinalizeChainKey
                    bobHolder.Session.FinalizeChainKey(senderKeyBytes.ToArray(), receiverKeyBytes.ToArray());
                }
                finally
                {
                    rootKeyBytes.Clear();
                    senderKeyBytes.Clear();
                    receiverKeyBytes.Clear();
                }

                bobHolder.Session.SetConnectionState(PubKeyExchangeState.Complete);
                _output.WriteLine($"[SETUP DR V2] Bob session {_bobSessionId} finalized.");
            }
            finally
            {
                bobHolder.Lock.Release();
            }


            // --- Final Verification ---
            _output.WriteLine("[SETUP DR V2] Verifying root keys match...");
            Assert.True(CompareSecureHandles(aliceRootKeyHandle, bobRootKeyHandle), "Derived root keys do NOT match!");
            _output.WriteLine("[SETUP DR V2] Handshake simulation complete & verified.");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"[SETUP DR V2] FAILED: {ex}");
            throw new InvalidOperationException("Test setup failed during granular handshake simulation.", ex);
        }
        finally
        {
            aliceRootKeyHandle?.Dispose();
            bobRootKeyHandle?.Dispose();
        }
    }


    Task IAsyncLifetime.DisposeAsync()
    {
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Ratchet_SendReceiveSingleMessage_Succeeds()
    {
        // InitializeAsync runs first via IAsyncLifetime
        _output.WriteLine("[Test: Ratchet_SendReceiveSingle] Running...");

        // Arrange
        var message = "Hello Bob! This is the first DR message.";
        var plaintextBytes = Encoding.UTF8.GetBytes(message);

        // Act: Alice sends using her established session
        _output.WriteLine($"[Test: Ratchet_SendReceiveSingle] Alice (Session {_aliceSessionId}) encrypting...");
        CipherPayload payload =
            await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, plaintextBytes);

        // Assert structure
        Assert.NotNull(payload);
        Assert.Equal(1u, payload.RatchetIndex); // First message after handshake
        Assert.Null(payload.DhPublicKey); // No DH rotation expected

        // Act: Bob receives using his established session
        _output.WriteLine($"[Test: Ratchet_SendReceiveSingle] Bob (Session {_bobSessionId}) decrypting...");
        byte[] decryptedBytes =
            await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload);

        // Assert
        Assert.Equal(plaintextBytes, decryptedBytes);
        _output.WriteLine("[Test: Ratchet_SendReceiveSingle] SUCCESS.");
    }

    [Fact]
    public async Task Ratchet_SendReceiveMultipleMessages_Succeeds()
    {
        // InitializeAsync runs first
        _output.WriteLine("[Test: Ratchet_SendReceiveMultiple] Running...");

        var messages = new[] { "DR Message 1", "Second DR", "Test DR 3" };
        var receivedMessages = new List<string>();

        for (int i = 0; i < messages.Length; i++)
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(messages[i]);
            _output.WriteLine($"[Test: Ratchet_SendReceiveMultiple] Alice sending message {i + 1}...");
            CipherPayload payload =
                await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, plaintextBytes);

            Assert.Equal((uint)(i + 1), payload.RatchetIndex);
            Assert.Equal(payload.DhPublicKey,ByteString.Empty);

            _output.WriteLine(
                $"[Test: Ratchet_SendReceiveMultiple] Bob receiving message {i + 1} (Index {payload.RatchetIndex})...");
            byte[] decryptedBytes =
                await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload);

            Assert.Equal(plaintextBytes, decryptedBytes);
            receivedMessages.Add(Encoding.UTF8.GetString(decryptedBytes));
        }

        Assert.Equal(messages, receivedMessages);
        _output.WriteLine("[Test: Ratchet_SendReceiveMultiple] SUCCESS.");
    }

    [Fact]
    public async Task Ratchet_SendReceiveBidirectional_Succeeds()
    {
        // InitializeAsync runs first
        _output.WriteLine("[Test: Ratchet_SendReceiveBidirectional] Running...");

        var msgAlice1 = "Hi Bob, from Alice DR";
        var msgBob1 = "Hi Alice, Bob DR here";
        var msgAlice2 = "How are you DR?";

        // Alice -> Bob (Msg 1)
        _output.WriteLine("[Bidirectional DR] Alice -> Bob (1)...");
        var payloadA1 = await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
            Encoding.UTF8.GetBytes(msgAlice1));
        Assert.Equal(1u, payloadA1.RatchetIndex);
        var decryptedB1 = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payloadA1);
        Assert.Equal(msgAlice1, Encoding.UTF8.GetString(decryptedB1));

        // Bob -> Alice (Msg 1)
        _output.WriteLine("[Bidirectional DR] Bob -> Alice (1)...");
        var payloadB1 =
            await _bobShieldPro.ProduceOutboundMessageAsync(_bobSessionId, _exchangeType,
                Encoding.UTF8.GetBytes(msgBob1));
        Assert.Equal(1u, payloadB1.RatchetIndex); // Bob's first message
        var decryptedA1 =
            await _aliceShieldPro.ProcessInboundMessageAsync(_aliceSessionId, _exchangeType, payloadB1);
        Assert.Equal(msgBob1, Encoding.UTF8.GetString(decryptedA1));

        // Alice -> Bob (Msg 2)
        _output.WriteLine("[Bidirectional DR] Alice -> Bob (2)...");
        var payloadA2 = await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
            Encoding.UTF8.GetBytes(msgAlice2));
        Assert.Equal(2u, payloadA2.RatchetIndex); // Alice's second message
        var decryptedB2 = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payloadA2);
        Assert.Equal(msgAlice2, Encoding.UTF8.GetString(decryptedB2));

        _output.WriteLine("[Test: Ratchet_SendReceiveBidirectional] SUCCESS.");
    }

    [Fact]
    public async Task Ratchet_ReceiveOutOfOrder_SucceedsWithinCache()
    {
        // InitializeAsync runs first
        _output.WriteLine("[Test: Ratchet_ReceiveOutOfOrder] Running...");

        var msg1 = "DR Message One";
        var msg2 = "DR Message Two";
        var msg3 = "DR Message Three";

        // Alice sends 1, 2, 3
        _output.WriteLine("[OutOfOrder DR] Alice sending 1, 2, 3...");
        var payload1 =
            await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                Encoding.UTF8.GetBytes(msg1));
        var payload2 =
            await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                Encoding.UTF8.GetBytes(msg2));
        var payload3 =
            await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType,
                Encoding.UTF8.GetBytes(msg3));
        Assert.Equal(1u, payload1.RatchetIndex);
        Assert.Equal(2u, payload2.RatchetIndex);
        Assert.Equal(3u, payload3.RatchetIndex);

        // Bob receives 3, then 1, then 2
        _output.WriteLine("[OutOfOrder DR] Bob receiving 3...");
        var dec3 = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload3);
        Assert.Equal(msg3, Encoding.UTF8.GetString(dec3));

        _output.WriteLine("[OutOfOrder DR] Bob receiving 1 (cached)...");
        var dec1 = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload1);
        Assert.Equal(msg1, Encoding.UTF8.GetString(dec1));

        _output.WriteLine("[OutOfOrder DR] Bob receiving 2 (cached)...");
        var dec2 = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload2);
        Assert.Equal(msg2, Encoding.UTF8.GetString(dec2));

        _output.WriteLine("[Test: Ratchet_ReceiveOutOfOrder] SUCCESS.");
    }

   

    // --- IAsyncDisposable for Test Class ---
    public async ValueTask DisposeAsync()
    {
        await _aliceShieldPro.DisposeAsync();
        await _bobShieldPro.DisposeAsync();
        _aliceKeys.Dispose();
        _bobKeys.Dispose();
        // Managers disposed via ShieldPro disposal
        GC.SuppressFinalize(this);
    }
}