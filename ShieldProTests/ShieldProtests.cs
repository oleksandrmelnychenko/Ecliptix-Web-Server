using System.Security.Cryptography;
using Xunit.Abstractions;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Protocol.Utilities;
using Ecliptix.Protobuf.PubKeyExchange;
using Google.Protobuf;

namespace ShieldProTests;

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
    public void CompleteExchange_Success_Should_FinalizeSessionAndReturnRootKey()
    {
        _output.WriteLine("[Test: CompleteExchange_Success] Running Corrected Flow...");
        var exchangeType = PubKeyExchangeOfType.AppDeviceEphemeralConnect; // Use actual enum value
        SodiumSecureMemoryHandle? aliceRootKeyHandle = null;
        SodiumSecureMemoryHandle? bobRootKeyHandle = null;

        try
        {
            // --- Step 1: Bob publishes his keys (Simulated by creating his bundle) ---
            _output.WriteLine("[Test Steps] Bob generates his public bundle...");
            // CreatePublicBundle returns the Protobuf type
            var bobPublicBundleProto = _bobKeys.CreatePublicBundle();
            if (bobPublicBundleProto == null) throw new InvalidOperationException("Bob failed to create bundle");

            // Alice will need Bob's bundle (as if fetched from server)
            // And Bob will need his *own* keys later for his calculation


            // --- Step 2: Alice initiates ---
            _output.WriteLine("[Test Steps] Alice initiates handshake...");
            // Alice generates her ephemeral key (stores secret internally)
            _aliceKeys.GenerateEphemeralKeyPair();
            // Alice creates her *own* initial public bundle including her ephemeral key
            var alicePublicBundleProto = _aliceKeys.CreatePublicBundle();
            if (alicePublicBundleProto == null)
                throw new InvalidOperationException("Alice failed to create bundle");

            // Alice converts Bob's Protobuf bundle to the internal record for derivation
            var bobBundleInternalResult =
                LocalPublicKeyBundle.FromProtobufExchange(bobPublicBundleProto.ToProtobufExchange());
            Assert.True(bobBundleInternalResult.IsOk,
                bobBundleInternalResult.IsErr
                    ? $"Failed parsing Bob's bundle: {bobBundleInternalResult.UnwrapErr()}"
                    : "Failed parsing Bob's bundle");
            var bobBundleInternal = bobBundleInternalResult.Unwrap();

            // Alice derives the shared secret using her keys and Bob's public bundle (internal format)
            // Note: X3dhDeriveSharedSecret uses the internally stored _ephemeralSecretKeyHandle for Alice
            _output.WriteLine("[Test Steps] Alice deriving secret...");
            var aliceDeriveResult =
                _aliceKeys.X3dhDeriveSharedSecret(bobBundleInternal, ShieldPro.X3dhInfo); // Access static member
            Assert.True(aliceDeriveResult.IsOk,
                aliceDeriveResult.IsErr
                    ? $"Alice derivation failed: {aliceDeriveResult.UnwrapErr()}"
                    : "Alice derivation failed");
            aliceRootKeyHandle = aliceDeriveResult.Unwrap(); // Keep handle

            // Alice creates the initial message to send to Bob
            // This message contains Alice's public bundle (IKa_pub, EKa_pub) and potentially OPKb ID
            var initialMessageToBob = new PubKeyExchange
            {
                RequestId = Helpers.GenerateRandomUInt32(true),
                State = PubKeyExchangeState.Init, // Or maybe a specific "Initiation" state
                OfType = exchangeType,
                // Payload contains ALICE's public keys (including her ephemeral one)
                Payload = alicePublicBundleProto.ToProtobufExchange().ToByteString(),
            };
            // Alice would also need to know which OPK of Bob's she used (if any)
            uint? opkIdUsedByAlice = bobBundleInternal.OneTimePreKeys.FirstOrDefault()?.PreKeyId;


            // --- Step 3: Bob receives Alice's message and calculates secret ---
            _output.WriteLine("[Test Steps] Bob receiving Alice's initial message and deriving secret...");
            // Bob parses Alice's bundle from the message payload
            var receivedAliceBundleProto =
                Helpers.ParseFromBytes<PublicKeyBundle>(initialMessageToBob.Payload
                    .ToByteArray());
            // Convert Alice's bundle to internal format if needed by CalculateSharedSecretAsRecipient
            // OR pass public keys directly if CalculateSharedSecretAsRecipient takes them

            // Bob derives the shared secret using his keys and Alice's public keys
            var bobDeriveResult = _bobKeys.CalculateSharedSecretAsRecipient(
                receivedAliceBundleProto.IdentityX25519PublicKey.ToByteArray(), // Alice's IKa_pub
                receivedAliceBundleProto.EphemeralX25519PublicKey.ToByteArray(), // Alice's Ea_pub
                opkIdUsedByAlice, // ID of Bob's OPK that Alice chose
                ShieldPro.X3dhInfo // Use same info string
            );
            Assert.True(bobDeriveResult.IsOk,
                bobDeriveResult.IsErr
                    ? $"Bob derivation failed: {bobDeriveResult.UnwrapErr()}"
                    : "Bob derivation failed");
            bobRootKeyHandle = bobDeriveResult.Unwrap(); // Keep handle


            // --- Assert ---
            _output.WriteLine("[Test Steps] Comparing derived secrets...");
            Assert.NotNull(aliceRootKeyHandle);
            Assert.False(aliceRootKeyHandle.IsInvalid);
            Assert.NotNull(bobRootKeyHandle);
            Assert.False(bobRootKeyHandle.IsInvalid);
            Assert.Equal(Constants.X25519KeySize, aliceRootKeyHandle.Length);
            Assert.Equal(Constants.X25519KeySize, bobRootKeyHandle.Length);

            Assert.True(CompareSecureHandles(aliceRootKeyHandle, bobRootKeyHandle),
                "Derived root keys do NOT match!");

            _output.WriteLine("[Test: CompleteExchange_Success] SUCCESS. Root keys match.");
        }
        finally
        {
            aliceRootKeyHandle?.Dispose();
            bobRootKeyHandle?.Dispose();
        }
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