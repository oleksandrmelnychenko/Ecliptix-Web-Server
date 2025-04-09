using System.Runtime.CompilerServices;
using System.Text;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.CipherPayload;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;

namespace ProtocolTests;

[TestClass]
public class ShieldProDoubleRatchetTests : IAsyncDisposable
{
    private readonly TestContext _testContext;
    private LocalKeyMaterial _aliceKeys;
    private LocalKeyMaterial _bobKeys;
    private ShieldSessionManager _aliceSessionManager;
    private ShieldSessionManager _bobSessionManager;
    private ShieldPro _aliceShieldPro;
    private ShieldPro _bobShieldPro;
    private uint _aliceSessionId;
    private uint _bobSessionId;
    private PubKeyExchangeOfType _exchangeType;

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

    public ShieldProDoubleRatchetTests(TestContext testContext)
    {
        _testContext = testContext;
    }

    public TestContext TestContext { get; set; }
    
    private static bool CompareSecureHandles(SodiumSecureMemoryHandle? handleA, SodiumSecureMemoryHandle? handleB)
    {
        if (ReferenceEquals(handleA, handleB)) return true;
        if (handleA == null || handleB == null) return false;
        if (handleA.IsInvalid || handleB.IsInvalid || handleA.Length != handleB.Length || handleA.Length == 0) return false;

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

    [TestInitialize]
    public async Task InitializeAsync()
    {
        _testContext.WriteLine("[SETUP DR V2] Initializing keys and managers...");
        _aliceKeys = new LocalKeyMaterial(5);
        _bobKeys = new LocalKeyMaterial(5);
        _aliceSessionManager = ShieldSessionManager.CreateWithCleanupTask();
        _bobSessionManager = ShieldSessionManager.CreateWithCleanupTask();
        _aliceShieldPro = new ShieldPro(_aliceKeys, _aliceSessionManager);
        _bobShieldPro = new ShieldPro(_bobKeys, _bobSessionManager);
        _exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect;

        _testContext.WriteLine("[SETUP DR V2] Performing simulated X3DH Handshake (granular)...");

        SodiumSecureMemoryHandle? aliceRootKeyHandle = null;
        SodiumSecureMemoryHandle? bobRootKeyHandle = null;

        try
        {
            PublicKeyBundle? bobPublicBundleProto = _bobKeys.CreatePublicBundle().ToProtobufExchange();
            if (bobPublicBundleProto == null) throw new InvalidOperationException("Bob failed create bundle");

            _aliceKeys.GenerateEphemeralKeyPair();
            PublicKeyBundle? alicePublicBundleProto = _aliceKeys.CreatePublicBundle().ToProtobufExchange();
            if (alicePublicBundleProto == null) throw new InvalidOperationException("Alice failed create bundle");

            _aliceSessionId = Helpers.GenerateRandomUInt32(true);
            ShieldSession aliceSession = new(_aliceSessionId, alicePublicBundleProto);
            _aliceSessionManager.InsertSessionOrThrow(_aliceSessionId, _exchangeType, aliceSession);

            Result<LocalPublicKeyBundle, ShieldError> bobBundleInternalResult = LocalPublicKeyBundle.FromProtobufExchange(bobPublicBundleProto);
            Assert.IsTrue(bobBundleInternalResult.IsOk, bobBundleInternalResult.IsErr ? $"Failed parsing Bob's bundle: {bobBundleInternalResult.UnwrapErr()}" : "Failed parsing Bob's bundle");
            LocalPublicKeyBundle bobBundleInternal = bobBundleInternalResult.Unwrap();

            Result<SodiumSecureMemoryHandle, ShieldFailure> aliceDeriveResult = _aliceKeys.X3dhDeriveSharedSecret(bobBundleInternal, ShieldPro.X3dhInfo);
            Assert.IsTrue(aliceDeriveResult.IsOk, aliceDeriveResult.IsErr ? $"Alice derivation failed: {aliceDeriveResult.UnwrapErr()}" : "Alice derivation failed");
            aliceRootKeyHandle = aliceDeriveResult.Unwrap();

            var aliceHolder = _aliceSessionManager.GetSessionHolderOrThrow(_aliceSessionId, _exchangeType);
            await aliceHolder.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (aliceHolder.Session.State != PubKeyExchangeState.Init)
                    throw new InvalidOperationException("Alice session not Init before finalize.");
                aliceHolder.Session.SetPeerBundle(bobPublicBundleProto);

                Span<byte> rootKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> senderKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> receiverKeyBytes = stackalloc byte[Constants.X25519KeySize];
                try
                {
                    aliceRootKeyHandle.Read(rootKeyBytes);
                    using (HkdfSha256 hkdfSender = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfSender.Expand(ShieldPro.SenderChainInfo, senderKeyBytes);
                    }
                    using (HkdfSha256 hkdfReceiver = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfReceiver.Expand(ShieldPro.ReceiverChainInfo, receiverKeyBytes);
                    }
                    aliceHolder.Session.FinalizeChainKey(senderKeyBytes.ToArray(), receiverKeyBytes.ToArray());
                }
                finally
                {
                    rootKeyBytes.Clear();
                    senderKeyBytes.Clear();
                    receiverKeyBytes.Clear();
                }
                aliceHolder.Session.SetConnectionState(PubKeyExchangeState.Complete);
                _testContext.WriteLine($"[SETUP DR V2] Alice session {_aliceSessionId} finalized.");
            }
            finally
            {
                aliceHolder.Lock.Release();
            }

            _bobSessionId = Helpers.GenerateRandomUInt32(true);
            PublicKeyBundle bobLocalBundleProto = _bobKeys.CreatePublicBundle().ToProtobufExchange();
            if (bobLocalBundleProto == null) throw new InvalidOperationException("Bob failed create bundle for session");
            ShieldSession bobSession = new(_bobSessionId, bobLocalBundleProto);
            _bobSessionManager.InsertSessionOrThrow(_bobSessionId, _exchangeType, bobSession);

            uint? opkIdUsedByAlice = bobBundleInternal.OneTimePreKeys.FirstOrDefault()?.PreKeyId;

            Result<SodiumSecureMemoryHandle, ShieldFailure> bobDeriveResult = _bobKeys.CalculateSharedSecretAsRecipient(
                alicePublicBundleProto.IdentityX25519PublicKey.ToByteArray(),
                alicePublicBundleProto.EphemeralX25519PublicKey.ToByteArray(),
                opkIdUsedByAlice,
                ShieldPro.X3dhInfo
            );
            Assert.IsTrue(bobDeriveResult.IsOk, bobDeriveResult.IsErr ? $"Bob derivation failed: {bobDeriveResult.UnwrapErr()}" : "Bob derivation failed");
            bobRootKeyHandle = bobDeriveResult.Unwrap();

            var bobHolder = _bobSessionManager.GetSessionHolderOrThrow(_bobSessionId, _exchangeType);
            await bobHolder.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (bobHolder.Session.State != PubKeyExchangeState.Init)
                    throw new InvalidOperationException("Bob session not Init before finalize.");
                bobHolder.Session.SetPeerBundle(alicePublicBundleProto);

                Span<byte> rootKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> senderKeyBytes = stackalloc byte[Constants.X25519KeySize];
                Span<byte> receiverKeyBytes = stackalloc byte[Constants.X25519KeySize];
                try
                {
                    bobRootKeyHandle.Read(rootKeyBytes);
                    using (HkdfSha256 hkdfSender = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfSender.Expand(ShieldPro.SenderChainInfo, senderKeyBytes);
                    }
                    using (HkdfSha256 hkdfReceiver = new HkdfSha256(rootKeyBytes, default))
                    {
                        hkdfReceiver.Expand(ShieldPro.ReceiverChainInfo, receiverKeyBytes);
                    }
                    bobHolder.Session.FinalizeChainKey(receiverKeyBytes.ToArray(), senderKeyBytes.ToArray()); // Swapped
                }
                finally
                {
                    rootKeyBytes.Clear();
                    senderKeyBytes.Clear();
                    receiverKeyBytes.Clear();
                }
                bobHolder.Session.SetConnectionState(PubKeyExchangeState.Complete);
                _testContext.WriteLine($"[SETUP DR V2] Bob session {_bobSessionId} finalized.");
            }
            finally
            {
                bobHolder.Lock.Release();
            }

            _testContext.WriteLine("[SETUP DR V2] Verifying root keys match...");
            Assert.IsTrue(CompareSecureHandles(aliceRootKeyHandle, bobRootKeyHandle), "Derived root keys do NOT match!");
            _testContext.WriteLine("[SETUP DR V2] Handshake simulation complete & verified.");
        }
        catch (Exception ex)
        {
            _testContext.WriteLine($"[SETUP DR V2] FAILED: {ex}");
            throw new InvalidOperationException("Test setup failed during granular handshake simulation.", ex);
        }
        finally
        {
            aliceRootKeyHandle?.Dispose();
            bobRootKeyHandle?.Dispose();
        }
    }

    [TestMethod]
    public async Task Ratchet_SendReceiveSingleMessage_Succeeds()
    {
        _testContext.WriteLine("[Test: Ratchet_SendReceiveSingle] Running...");

        const string message = "Hello Bob! This is the first DR message.";
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);

        _testContext.WriteLine($"[Test: Ratchet_SendReceiveSingle] Alice (Session {_aliceSessionId}) encrypting...");
        CipherPayload payload = await _aliceShieldPro.ProduceOutboundMessageAsync(_aliceSessionId, _exchangeType, plaintextBytes);

        Assert.IsNotNull(payload);
        Assert.AreEqual(1u, payload.RatchetIndex);
        Assert.AreEqual(payload.DhPublicKey, ByteString.Empty);

        _testContext.WriteLine($"[Test: Ratchet_SendReceiveSingle] Bob (Session {_bobSessionId}) decrypting...");
        byte[] decryptedBytes = await _bobShieldPro.ProcessInboundMessageAsync(_bobSessionId, _exchangeType, payload);
        string decrypted = Encoding.UTF8.GetString(decryptedBytes);
        
        Assert.AreEqual(decrypted, message);
        _testContext.WriteLine("[Test: Ratchet_SendReceiveSingle] SUCCESS.");
    }
    
    public async ValueTask DisposeAsync()
    {
        await _aliceShieldPro.DisposeAsync();
        await _bobShieldPro.DisposeAsync();
        _aliceKeys.Dispose();
        _bobKeys.Dispose();
        GC.SuppressFinalize(this);
    }

    [TestCleanup]
    public async Task CleanupAsync()
    {
        await DisposeAsync();
    }
}