using System.Security.Cryptography;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;

namespace ProtocolTests;

[TestClass]
public class ShieldProTests : IAsyncDisposable
{
    private readonly TestContext _testContext;
    private readonly EcliptixSystemIdentityKeys _aliceKeys;
    private readonly EcliptixSystemIdentityKeys _bobKeys;
    private readonly ShieldPro _aliceShieldPro;
    private readonly ShieldPro _bobShieldPro;

    static ShieldProTests()
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

    public ShieldProTests(TestContext testContext)
    {
        TestContext = testContext;
        _testContext = TestContext; // MSTest provides TestContext automatically
        _aliceKeys =  EcliptixSystemIdentityKeys.Create(5).Unwrap();
        _bobKeys =EcliptixSystemIdentityKeys.Create(5).Unwrap();
        ShieldSessionManager aliceSessionManager = ShieldSessionManager.Create();
        ShieldSessionManager bobSessionManager = ShieldSessionManager.Create();
        _aliceShieldPro = new ShieldPro(_aliceKeys, aliceSessionManager);
        _bobShieldPro = new ShieldPro(_bobKeys, bobSessionManager);
    }

    public TestContext TestContext { get; set; } // Required property for MSTest to inject TestContext

    private static byte[] CorruptBytes(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty) return [];
        byte[] corrupted = input.ToArray();
        const int indexToCorrupt = 0;
        corrupted[indexToCorrupt] ^= 0xFF;
        return corrupted;
    }

    private static byte[] GenerateNonce()
    {
        return RandomNumberGenerator.GetBytes(Constants.AesGcmNonceSize);
    }

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

    private static byte[] GenerateData(int size)
    {
        return size switch
        {
            < 0 => throw new ArgumentOutOfRangeException(nameof(size)),
            0 => [],
            _ => RandomNumberGenerator.GetBytes(size)
        };
    }

    [TestMethod]
    public void CompleteExchange_Success_Should_FinalizeSessionAndReturnRootKey()
    {
        const PubKeyExchangeType exchangeType = PubKeyExchangeType.AppDeviceEphemeralConnect;
        SodiumSecureMemoryHandle? aliceRootKeyHandle = null;
        SodiumSecureMemoryHandle? bobRootKeyHandle = null;

        try
        {
            LocalPublicKeyBundle? bobPublicBundleProto = _bobKeys.CreatePublicBundle().Unwrap();
            if (bobPublicBundleProto == null) throw new InvalidOperationException("Bob failed to create public bundle");

            _aliceKeys.GenerateEphemeralKeyPair();
            LocalPublicKeyBundle? alicePublicBundleProto = _aliceKeys.CreatePublicBundle().Unwrap();
            if (alicePublicBundleProto == null) throw new InvalidOperationException("Alice failed to create bundle");

            Result<LocalPublicKeyBundle, ShieldFailure> bobBundleInternalResult =
                LocalPublicKeyBundle.FromProtobufExchange(bobPublicBundleProto.ToProtobufExchange());
            Assert.IsTrue(bobBundleInternalResult.IsOk,
                bobBundleInternalResult.IsErr
                    ? $"Failed parsing Bob's bundle: {bobBundleInternalResult.UnwrapErr()}"
                    : "Failed parsing Bob's bundle");
            LocalPublicKeyBundle bobBundleInternal = bobBundleInternalResult.Unwrap();

            Result<SodiumSecureMemoryHandle, ShieldFailure> aliceDeriveResult =
                _aliceKeys.X3dhDeriveSharedSecret(bobBundleInternal, ShieldPro.X3dhInfo);
            Assert.IsTrue(aliceDeriveResult.IsOk,
                aliceDeriveResult.IsErr
                    ? $"Alice derivation failed: {aliceDeriveResult.UnwrapErr()}"
                    : "Alice derivation failed");
            aliceRootKeyHandle = aliceDeriveResult.Unwrap();

            PubKeyExchange initialMessageToBob = new()
            {
                RequestId = Helpers.GenerateRandomUInt32(true),
                State = PubKeyExchangeState.Init,
                OfType = exchangeType,
                Payload = alicePublicBundleProto.ToProtobufExchange().ToByteString(),
            };
            uint? opkIdUsedByAlice = bobBundleInternal.OneTimePreKeys.FirstOrDefault()?.PreKeyId;

            PublicKeyBundle receivedAliceBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(initialMessageToBob.Payload.ToByteArray());
            Result<SodiumSecureMemoryHandle, ShieldFailure> bobDeriveResult = _bobKeys.CalculateSharedSecretAsRecipient(
                receivedAliceBundleProto.IdentityX25519PublicKey.ToByteArray(),
                receivedAliceBundleProto.EphemeralX25519PublicKey.ToByteArray(),
                opkIdUsedByAlice,
                ShieldPro.X3dhInfo
            );
            Assert.IsTrue(bobDeriveResult.IsOk,
                bobDeriveResult.IsErr
                    ? $"Bob derivation failed: {bobDeriveResult.UnwrapErr()}"
                    : "Bob derivation failed");
            bobRootKeyHandle = bobDeriveResult.Unwrap();

            Assert.IsNotNull(aliceRootKeyHandle);
            Assert.IsFalse(aliceRootKeyHandle.IsInvalid);
            Assert.IsNotNull(bobRootKeyHandle);
            Assert.IsFalse(bobRootKeyHandle.IsInvalid);
            Assert.AreEqual(Constants.X25519KeySize, aliceRootKeyHandle.Length);
            Assert.AreEqual(Constants.X25519KeySize, bobRootKeyHandle.Length);
            Assert.IsTrue(CompareSecureHandles(aliceRootKeyHandle, bobRootKeyHandle), "Derived root keys do NOT match!");
        }
        finally
        {
            aliceRootKeyHandle?.Dispose();
            bobRootKeyHandle?.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _aliceShieldPro.DisposeAsync();
        await _bobShieldPro.DisposeAsync();
        _aliceKeys.Dispose();
        _bobKeys.Dispose();
        GC.SuppressFinalize(this);
    }
}