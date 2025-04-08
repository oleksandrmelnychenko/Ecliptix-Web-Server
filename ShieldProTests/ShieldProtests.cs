using System.Security.Cryptography;
using Xunit.Abstractions;
using System.Text;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Ecliptix.Protobuf.CipherPayload;
using Google.Protobuf;
using ProtoBuf.WellKnownTypes;

namespace ShieldProTests
{
    public class ShieldProTests : IAsyncDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly LocalKeyMaterial _aliceKeys;

        private readonly LocalKeyMaterial _bobKeys;

        // FIX: Separate Session Managers
        private readonly ShieldSessionManager _aliceSessionManager;
        private readonly ShieldSessionManager _bobSessionManager;
        private readonly ShieldPro _aliceShieldPro;
        private readonly ShieldPro _bobShieldPro;

        // Static init for Sodium
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

        public ShieldProTests(ITestOutputHelper output)
        {
            _output = output;
            _aliceKeys = new LocalKeyMaterial(5);
            _bobKeys = new LocalKeyMaterial(5);

            // FIX: Create separate managers
            _aliceSessionManager = ShieldSessionManager.CreateWithCleanupTask();
            _bobSessionManager = ShieldSessionManager.CreateWithCleanupTask();

            // FIX: Inject the correct manager into each ShieldPro instance
            _aliceShieldPro = new ShieldPro(_aliceKeys, _aliceSessionManager);
            _bobShieldPro = new ShieldPro(_bobKeys, _bobSessionManager);
        }

        private static byte[] CorruptBytes(ReadOnlySpan<byte> input)
        {
            if (input.IsEmpty) return Array.Empty<byte>();
            var corrupted = input.ToArray();
            // Ensure corruption happens even for 1-byte inputs
            int indexToCorrupt = 0;
            // Optional: Make corruption slightly more robust for testing if needed
            // if (corrupted.Length > 1) { indexToCorrupt = corrupted.Length / 2; }
            corrupted[indexToCorrupt] ^= 0xFF; // Flip a byte
            return corrupted;
        }

        // FIX: Added full implementation
        private static byte[] GenerateNonce()
        {
            // Ensure this matches the expected nonce size for your AEAD scheme
            return RandomNumberGenerator.GetBytes(Constants.AesGcmNonceSize);
        }

        // FIX: Added full implementation (using Read, not GetSpan)
        private static bool CompareSecureHandles(SodiumSecureMemoryHandle? handleA, SodiumSecureMemoryHandle? handleB)
        {
            if (ReferenceEquals(handleA, handleB)) return true;
            if (handleA == null || handleB == null) return false;
            if (handleA.IsInvalid || handleB.IsInvalid || handleA.Length != handleB.Length ||
                handleA.Length == 0) return false;

            // Use stackalloc for temporary read buffers
            // Ensure Length is not excessively large for stackalloc if keys could vary wildly
            // For fixed-size crypto keys (like 32 bytes), this is perfectly safe.
            if (handleA.Length > 1024) // Add a safety check for stackalloc size
            {
                // Fallback to heap allocation for very large handles if necessary
                byte[] bytesA_heap = new byte[handleA.Length];
                byte[] bytesB_heap = new byte[handleB.Length];
                try
                {
                    handleA.Read(bytesA_heap);
                    handleB.Read(bytesB_heap);
                    return bytesA_heap.SequenceEqual(bytesB_heap);
                }
                finally
                {
                    SodiumInterop.SecureWipe(bytesA_heap);
                    SodiumInterop.SecureWipe(bytesB_heap);
                }
            }

            Span<byte> bytesA = stackalloc byte[handleA.Length];
            Span<byte> bytesB = stackalloc byte[handleB.Length];
            bool equal = false;

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
                bytesA.Clear(); // Clear stack buffers
                bytesB.Clear();
            }

            return equal;
        }

        // FIX: Added full implementation
        private static byte[] GenerateData(int size)
        {
            if (size < 0) throw new ArgumentOutOfRangeException(nameof(size));
            if (size == 0) return Array.Empty<byte>();
            return RandomNumberGenerator.GetBytes(size);
        }


        [Fact]
        public async Task CompleteExchange_Success_Should_FinalizeSessionAndReturnRootKey()
        {
            // ... (Setup Alice and Bob, Begin exchange for both) ...
            _output.WriteLine("[Test: CompleteExchange_Success] Running...");
            var exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect;
            (uint aliceSessionId, PubKeyExchange aliceInitialMsg) =
                await _aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(exchangeType);
            (uint bobSessionId, PubKeyExchange bobInitialMsg) =
                await _bobShieldPro.BeginDataCenterPubKeyExchangeAsync(exchangeType);
            SodiumSecureMemoryHandle? aliceRootKeyHandle = null;
            SodiumSecureMemoryHandle? bobRootKeyHandle = null;

            // Parse bundles for verification
            var aliceBundleProto =
                Helpers.ParseFromBytes<Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle>(aliceInitialMsg.Payload
                    .ToByteArray());
            var aliceBundleInternalResult = LocalPublicKeyBundle.FromProtobufExchange(aliceBundleProto);
            Assert.True(aliceBundleInternalResult.IsOk, "Failed parsing Alice's bundle");
            var aliceBundleInternal = aliceBundleInternalResult.Unwrap();

            var bobBundleProto =
                Helpers.ParseFromBytes<Ecliptix.Protobuf.PubKeyExchange.PublicKeyBundle>(bobInitialMsg.Payload
                    .ToByteArray());
            var bobBundleInternalResult = LocalPublicKeyBundle.FromProtobufExchange(bobBundleProto);
            Assert.True(bobBundleInternalResult.IsOk, "Failed parsing Bob's bundle");
            var bobBundleInternal = bobBundleInternalResult.Unwrap();

            uint? opkIdUsedByAlice = bobBundleInternal.OneTimePreKeys.FirstOrDefault()?.PreKeyId;
            // ... (OPK ID logging) ...


            // ***** VERIFY INPUT KEYS BEFORE DERIVATION *****
            _output.WriteLine("--- Verifying Keys Before Derivation ---");

            // Verify Alice's Identity Key (IKa) consistency
            _output.WriteLine($"Alice IKa Pub (Direct):   {Convert.ToHexString(_aliceKeys.IdentityX25519PublicKey)}");
            _output.WriteLine($"Alice IKa Pub (Bundle):   {Convert.ToHexString(aliceBundleInternal.IdentityX25519)}");
            Assert.Equal(_aliceKeys.IdentityX25519PublicKey,
                aliceBundleInternal.IdentityX25519); // Alice's bundle has her correct IK_pub

            // Verify Bob's Signed PreKey (SPKb) consistency
            _output.WriteLine($"Bob SPKb Pub (Direct):    {Convert.ToHexString(_bobKeys.SignedPreKeyPublic)}");
            _output.WriteLine($"Bob SPKb Pub (Bundle):    {Convert.ToHexString(bobBundleInternal.SignedPreKeyPublic)}");
            Assert.Equal(_bobKeys.SignedPreKeyPublic,
                bobBundleInternal.SignedPreKeyPublic); // Bob's bundle has his correct SPK_pub

            // Verify Alice's Ephemeral Key (Ea) consistency (used in Bob's calculation)
            Assert.NotNull(aliceBundleInternal.EphemeralX25519);
            _output.WriteLine(
                $"Alice Ea Pub (Direct):    {Convert.ToHexString(_aliceKeys.EphemeralX25519PublicKey!)}"); // Use ! as GenerateEphemeralKeyPair was called
            _output.WriteLine($"Alice Ea Pub (Bundle):    {Convert.ToHexString(aliceBundleInternal.EphemeralX25519!)}");
            Assert.Equal(_aliceKeys.EphemeralX25519PublicKey, aliceBundleInternal.EphemeralX25519);

            // Verify Bob's Identity Key (IKb) consistency (used in Alice's calculation)
            _output.WriteLine($"Bob IKb Pub (Direct):     {Convert.ToHexString(_bobKeys.IdentityX25519PublicKey)}");
            _output.WriteLine($"Bob IKb Pub (Bundle):     {Convert.ToHexString(bobBundleInternal.IdentityX25519)}");
            Assert.Equal(_bobKeys.IdentityX25519PublicKey, bobBundleInternal.IdentityX25519);
            _output.WriteLine("--- Key Verification Complete ---");
            // ***** END VERIFICATION *****


            try
            {
                // ... (Alice's Complete... call as before) ...
                (_, aliceRootKeyHandle) =
                    await _aliceShieldPro.CompleteDataCenterPubKeyExchangeAsync(aliceSessionId, exchangeType,
                        bobInitialMsg);


                // ... (Bob's temporary workaround derivation call as before) ...
                var bobDeriveResult = _bobKeys.CalculateSharedSecretAsRecipient(
                    aliceBundleInternal.IdentityX25519, // Alice's IKa_pub from HER bundle
                    aliceBundleInternal.EphemeralX25519!, // Alice's Ea_pub from HER bundle
                    opkIdUsedByAlice,
                    ShieldPro.X3dhInfo // Access static member correctly
                );
                Assert.True(bobDeriveResult.IsOk,
                    $"Bob derivation failed: {bobDeriveResult.UnwrapErr()}"); // Use conditional format
                bobRootKeyHandle = bobDeriveResult.Unwrap();


                // Final assertion
                Assert.True(CompareSecureHandles(aliceRootKeyHandle, bobRootKeyHandle), "Root keys mismatch!");
                _output.WriteLine("[Test: CompleteExchange_Success] SUCCESS.");
            }
            finally
            {
                aliceRootKeyHandle?.Dispose();
                bobRootKeyHandle?.Dispose();
            }
        }


        [Fact]
        public async Task CompleteExchange_Fail_IfSessionNotInInitState()
        {
            _output.WriteLine("[Test: CompleteExchange_Fail_WrongState] Running...");

            PubKeyExchangeOfType exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect;

            (uint aliceSessionId, PubKeyExchange aliceInitialMsg) =
                await _aliceShieldPro.BeginDataCenterPubKeyExchangeAsync(exchangeType);

            (uint bobSessionId, PubKeyExchange bobInitialMsg) =
                await _bobShieldPro.BeginDataCenterPubKeyExchangeAsync(exchangeType);

            // Complete Alice's side first, setting state to Complete
            (_, SodiumSecureMemoryHandle aliceRoot) =
                await _aliceShieldPro.CompleteDataCenterPubKeyExchangeAsync(aliceSessionId, exchangeType,
                    bobInitialMsg);
            aliceRoot.Dispose();

            // Act & Assert: Try to complete Alice's side again
            _output.WriteLine(
                $"[Test: CompleteExchange_Fail_WrongState] Alice completing session {aliceSessionId} again...");
            var ex = await Assert.ThrowsAsync<ShieldChainStepException>(() =>
                _aliceShieldPro.CompleteDataCenterPubKeyExchangeAsync(aliceSessionId, exchangeType, bobInitialMsg)
            );

            // FIX: Assert the correct message thrown by the Complete... method's internal logic
            Assert.Contains($"Session {aliceSessionId} not in Init state", ex.Message);

            _output.WriteLine("[Test: CompleteExchange_Fail_WrongState] SUCCESS.");
        }

        // --- IAsyncDisposable for Test Class ---
        public async ValueTask DisposeAsync()
        {
            // Dispose instances created in constructor
            await _aliceShieldPro.DisposeAsync();
            await _bobShieldPro.DisposeAsync();
            // Dispose the managers explicitly if ShieldPro doesn't own them exclusively
            // (In this setup, ShieldPro creates default managers if null, so it effectively owns them)
            // If you passed an externally created manager, you might not dispose it here.
            // await _aliceSessionManager.DisposeAsync(); // Already handled by _aliceShieldPro.DisposeAsync
            // await _bobSessionManager.DisposeAsync(); // Already handled by _bobShieldPro.DisposeAsync

            _aliceKeys.Dispose();
            _bobKeys.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}