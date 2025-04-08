using Xunit.Abstractions;
using System.Text;
using Ecliptix.Core.Protocol;

namespace ShieldProTests;

public class X3dhKeyAgreementTests
{
    private readonly ITestOutputHelper _output;

    public X3dhKeyAgreementTests(ITestOutputHelper output)
    {
        _output = output;
        try
        {
            Sodium.SodiumCore.Init();
        }
        catch (Exception ex)
        {
            _output.WriteLine($"FATAL Sodium Init: {ex.Message}");
            throw;
        }
    }

    private static byte[] GenerateRandomInfo() => Encoding.UTF8.GetBytes($"TestContext-{Guid.NewGuid()}");

    private static bool CompareSecrets(SodiumSecureMemoryHandle? handleA, SodiumSecureMemoryHandle? handleB)
    {
        if (handleA == null || handleB == null || handleA.IsInvalid || handleB.IsInvalid ||
            handleA.Length != handleB.Length) return false;
        byte[]? bytesA = null;
        byte[]? bytesB = null;
        try
        {
            bytesA = new byte[handleA.Length];
            handleA.Read(bytesA);
            bytesB = new byte[handleB.Length];
            handleB.Read(bytesB);
            return bytesA.SequenceEqual(bytesB);
        }
        finally
        {
            if (bytesA != null) SodiumInterop.SecureWipe(bytesA);
            if (bytesB != null) SodiumInterop.SecureWipe(bytesB);
        }
    }

    private static byte[] CorruptBytes(byte[] input)
    {
        if (input == null || input.Length == 0) return Array.Empty<byte>();
        var corrupted = (byte[])input.Clone();
        corrupted[0] ^= 0xFF;
        return corrupted;
    }

    [Fact]
    public void X3DH_Success_OPK_Used()
    {
        // Arrange
        _output.WriteLine("[Test: Success_OPK_Used] Setting up Alice and Bob...");
        using var aliceMaterial = new LocalKeyMaterial(10);
        using var bobMaterial = new LocalKeyMaterial(5);

        byte[] aliceEphemeralPublic = aliceMaterial.GenerateEphemeralKeyPair();
        var bobFullPublicBundle = bobMaterial.CreatePublicBundle();
        var selectedBobOpk = bobFullPublicBundle.OneTimePreKeys.First();
        uint selectedBobOpkId = selectedBobOpk.PreKeyId;
        _output.WriteLine($"[Test: Success_OPK_Used] Server selected Bob's OPK ID: {selectedBobOpkId}");

        var bundleForAlice = new LocalPublicKeyBundle(bobFullPublicBundle.IdentityEd25519,
            bobFullPublicBundle.IdentityX25519, bobFullPublicBundle.SignedPreKeyId,
            bobFullPublicBundle.SignedPreKeyPublic, bobFullPublicBundle.SignedPreKeySignature,
            new List<OneTimePreKeyRecord> { selectedBobOpk }, null);
        byte[] hkdfInfo = GenerateRandomInfo();

        SodiumSecureMemoryHandle? aliceDerivedSecretHandle = null;
        SodiumSecureMemoryHandle? bobDerivedSecretHandle = null;

        try
        {
            // Act: Alice
            _output.WriteLine("[Test: Success_OPK_Used] Alice calculating...");
            var aliceResult = aliceMaterial.X3dhDeriveSharedSecret(bundleForAlice, hkdfInfo);
            Assert.True(aliceResult.IsOk,
                $"Alice failed: {(aliceResult.IsOk ? "" : aliceResult.UnwrapErr().ToString())}");
            aliceDerivedSecretHandle = aliceResult.Unwrap();
            Assert.False(aliceDerivedSecretHandle.IsInvalid);

            // Act: Bob
            _output.WriteLine("[Test: Success_OPK_Used] Bob calculating...");
            var bobResult = bobMaterial.CalculateSharedSecretAsRecipient(aliceMaterial.IdentityX25519PublicKey,
                aliceEphemeralPublic, selectedBobOpkId, hkdfInfo); // Pass ID
            Assert.True(bobResult.IsOk, $"Bob failed: {(bobResult.IsOk ? "" : bobResult.UnwrapErr().ToString())}");
            bobDerivedSecretHandle = bobResult.Unwrap();
            Assert.False(bobDerivedSecretHandle.IsInvalid);

            // Assert
            _output.WriteLine("[Test: Success_OPK_Used] Comparing secrets...");
            Assert.True(CompareSecrets(aliceDerivedSecretHandle, bobDerivedSecretHandle), "Secrets do NOT match!");
            _output.WriteLine("[Test: Success_OPK_Used] SUCCESS: Secrets match.");
        }
        finally
        {
            aliceDerivedSecretHandle?.Dispose();
            bobDerivedSecretHandle?.Dispose();
        }
    }

    [Fact]
    public void X3DH_Success_No_OPK_Used()
    {
        // Arrange
        _output.WriteLine("[Test: Success_No_OPK_Used] Setting up Alice and Bob...");
        using var aliceMaterial = new LocalKeyMaterial(10);
        using var bobMaterial = new LocalKeyMaterial(0); // Bob generates material with ZERO OPKs initially

        byte[] aliceEphemeralPublic = aliceMaterial.GenerateEphemeralKeyPair();
        var bobPublicBundleNoOpk = bobMaterial.CreatePublicBundle(); // Bundle will have empty OPK list
        Assert.Empty(bobPublicBundleNoOpk.OneTimePreKeys); // Verify no OPKs

        byte[] hkdfInfo = GenerateRandomInfo();
        _output.WriteLine($"[Test: Success_No_OPK_Used] Using HKDF Info: {Encoding.UTF8.GetString(hkdfInfo)}");

        SodiumSecureMemoryHandle? aliceDerivedSecretHandle = null;
        SodiumSecureMemoryHandle? bobDerivedSecretHandle = null;

        try
        {
            // Act: Alice (should succeed even with empty OPK list in bundle)
            _output.WriteLine("[Test: Success_No_OPK_Used] Alice calculating...");
            var aliceResult = aliceMaterial.X3dhDeriveSharedSecret(bobPublicBundleNoOpk, hkdfInfo);
            Assert.True(aliceResult.IsOk,
                $"Alice failed (no OPK): {(aliceResult.IsOk ? "" : aliceResult.UnwrapErr().ToString())}");
            aliceDerivedSecretHandle = aliceResult.Unwrap();
            Assert.False(aliceDerivedSecretHandle.IsInvalid);

            // Act: Bob (pass null for used OPK ID)
            _output.WriteLine("[Test: Success_No_OPK_Used] Bob calculating...");
            var bobResult = bobMaterial.CalculateSharedSecretAsRecipient(aliceMaterial.IdentityX25519PublicKey,
                aliceEphemeralPublic, null, hkdfInfo); // Pass null ID
            Assert.True(bobResult.IsOk,
                $"Bob failed (no OPK): {(bobResult.IsOk ? "" : bobResult.UnwrapErr().ToString())}");
            bobDerivedSecretHandle = bobResult.Unwrap();
            Assert.False(bobDerivedSecretHandle.IsInvalid);

            // Assert
            _output.WriteLine("[Test: Success_No_OPK_Used] Comparing secrets...");
            Assert.True(CompareSecrets(aliceDerivedSecretHandle, bobDerivedSecretHandle),
                "Secrets do NOT match (no OPK case)!");
            _output.WriteLine("[Test: Success_No_OPK_Used] SUCCESS: Secrets match.");
        }
        finally
        {
            aliceDerivedSecretHandle?.Dispose();
            bobDerivedSecretHandle?.Dispose();
        }
    }

    [Fact]
    public void X3DH_Fail_Invalid_SPK_Signature()
    {
        // Arrange
        _output.WriteLine("[Test: Fail_Invalid_SPK_Signature] Setting up Alice and Bob...");
        using var aliceMaterial = new LocalKeyMaterial(10); // Not used for calculation
        using var bobMaterial = new LocalKeyMaterial(5);

        var bobBundle = bobMaterial.CreatePublicBundle();
        var corruptedSignature = CorruptBytes(bobBundle.SignedPreKeySignature); // Modify the signature

        _output.WriteLine("[Test: Fail_Invalid_SPK_Signature] Verifying corrupted signature...");

        // Act & Assert: Call the static verification method
        var verificationResult = LocalKeyMaterial.VerifyRemoteSpkSignature(
            bobBundle.IdentityEd25519,
            bobBundle.SignedPreKeyPublic,
            corruptedSignature // Pass the bad signature
        );

        Assert.True(verificationResult.IsOk,
            "Verification failed unexpectedly."); // Check the Result wrapper itself didn't fail
        Assert.False(verificationResult.Unwrap(),
            "Invalid SPK signature was incorrectly verified as valid."); // Check the boolean value
        _output.WriteLine("[Test: Fail_Invalid_SPK_Signature] SUCCESS: Invalid signature correctly detected.");
    }

    [Fact]
    public void X3DH_Fail_BobCalculation_Invalid_OpkId()
    {
        // Arrange
        _output.WriteLine("[Test: Fail_Bob_Invalid_OpkId] Setting up Alice and Bob...");
        using var aliceMaterial = new LocalKeyMaterial(10);
        using var bobMaterial = new LocalKeyMaterial(5);

        byte[] aliceEphemeralPublic = aliceMaterial.GenerateEphemeralKeyPair();
        var bobBundle = bobMaterial.CreatePublicBundle();
        uint invalidOpkId = 99999; // An ID Bob doesn't have
        byte[] hkdfInfo = GenerateRandomInfo();

        _output.WriteLine($"[Test: Fail_Bob_Invalid_OpkId] Bob calculating with invalid OPK ID: {invalidOpkId}");

        // Act: Bob tries to calculate with a non-existent OPK ID
        var bobResult = bobMaterial.CalculateSharedSecretAsRecipient(
            aliceMaterial.IdentityX25519PublicKey,
            aliceEphemeralPublic,
            invalidOpkId, // Pass invalid ID
            hkdfInfo);

        // Assert
        Assert.True(bobResult.IsErr, "Bob's calculation succeeded with an invalid OPK ID.");
        Assert.Contains("not found or invalid", bobResult.UnwrapErr().Message); // Check error message content
        _output.WriteLine("[Test: Fail_Bob_Invalid_OpkId] SUCCESS: Bob failed as expected with invalid OPK ID.");
    }


    [Fact]
    public void X3DH_Fail_Empty_HkdfInfo()
    {
        // Arrange
        _output.WriteLine("[Test: Fail_Empty_HkdfInfo] Setting up Alice and Bob...");
        using var aliceMaterial = new LocalKeyMaterial(10);
        using var bobMaterial = new LocalKeyMaterial(5);

        byte[] aliceEphemeralPublic = aliceMaterial.GenerateEphemeralKeyPair();
        var bobFullPublicBundle = bobMaterial.CreatePublicBundle();
        var selectedBobOpk = bobFullPublicBundle.OneTimePreKeys.First();
        uint selectedBobOpkId = selectedBobOpk.PreKeyId;
        var bundleForAlice = new LocalPublicKeyBundle(bobFullPublicBundle.IdentityEd25519,
            bobFullPublicBundle.IdentityX25519, bobFullPublicBundle.SignedPreKeyId,
            bobFullPublicBundle.SignedPreKeyPublic, bobFullPublicBundle.SignedPreKeySignature,
            new List<OneTimePreKeyRecord> { selectedBobOpk }, null);

        byte[] emptyInfo = Array.Empty<byte>();

        _output.WriteLine("[Test: Fail_Empty_HkdfInfo] Alice calculating with empty info...");

        // Act & Assert: Alice
        var aliceResult = aliceMaterial.X3dhDeriveSharedSecret(bundleForAlice, emptyInfo);
        Assert.True(aliceResult.IsErr, "Alice succeeded with empty HKDF info.");
        Assert.Contains("HKDF info parameter cannot be empty", aliceResult.UnwrapErr().Message);

        _output.WriteLine("[Test: Fail_Empty_HkdfInfo] Bob calculating with empty info...");

        // Act & Assert: Bob
        var bobResult = bobMaterial.CalculateSharedSecretAsRecipient(aliceMaterial.IdentityX25519PublicKey,
            aliceEphemeralPublic, selectedBobOpkId, emptyInfo);
        Assert.True(bobResult.IsErr, "Bob succeeded with empty HKDF info.");
        Assert.Contains("HKDF info parameter cannot be empty", bobResult.UnwrapErr().Message);

        _output.WriteLine("[Test: Fail_Empty_HkdfInfo] SUCCESS: Both failed as expected with empty HKDF info.");
    }

    [Fact]
    public void LocalKeyMaterial_Fail_UseAfterDispose()
    {
        // Arrange
        _output.WriteLine("[Test: Fail_UseAfterDispose] Setting up material...");
        var material = new LocalKeyMaterial(5);
        _output.WriteLine("[Test: Fail_UseAfterDispose] Disposing material...");
        material.Dispose(); // Dispose it explicitly

        _output.WriteLine("[Test: Fail_UseAfterDispose] Attempting to use after dispose...");

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => material.GenerateEphemeralKeyPair());
        Assert.Throws<ObjectDisposedException>(() => material.CreatePublicBundle());
        // Add more checks for other methods if needed

        _output.WriteLine("[Test: Fail_UseAfterDispose] SUCCESS: ObjectDisposedException thrown as expected.");
    }


    // --- Loop Test ---
    [Fact]
    public void X3DH_Loop_100_Pairs_SecretsShouldMatch()
    {
        _output.WriteLine("[Test: Loop_100_Pairs] Starting loop test...");
        int iterations = 100;
        int successCount = 0;

        for (int i = 0; i < iterations; i++)
        {
            _output.WriteLine($"[Test: Loop_100_Pairs] Iteration {i + 1}/{iterations}");
            SodiumSecureMemoryHandle? aliceHandle = null;
            SodiumSecureMemoryHandle? bobHandle = null;
            bool iterationSuccess = false;

            // Use try/catch/finally within the loop to isolate failures and ensure cleanup
            try
            {
                using var aliceMat = new LocalKeyMaterial(2); // Fewer OPKs for loop efficiency
                using var bobMat = new LocalKeyMaterial(1);

                byte[] aliceEphPub = aliceMat.GenerateEphemeralKeyPair();
                var bobBundleFull = bobMat.CreatePublicBundle();
                var bobOpk =
                    bobBundleFull.OneTimePreKeys
                        .FirstOrDefault(); // Handle case where Bob might have 0 if count was 0
                uint? bobOpkId = bobOpk?.PreKeyId;

                var bundleForAlice = new LocalPublicKeyBundle(bobBundleFull.IdentityEd25519,
                    bobBundleFull.IdentityX25519, bobBundleFull.SignedPreKeyId, bobBundleFull.SignedPreKeyPublic,
                    bobBundleFull.SignedPreKeySignature,
                    bobOpk != null ? new List<OneTimePreKeyRecord> { bobOpk } : new List<OneTimePreKeyRecord>(),
                    null);

                byte[] info = GenerateRandomInfo();

                // Alice
                var aliceRes = aliceMat.X3dhDeriveSharedSecret(bundleForAlice, info);
                if (aliceRes.IsErr)
                {
                    _output.WriteLine($"[Loop Iteration {i + 1}] Alice Error: {aliceRes.UnwrapErr()}");
                    continue;
                } // Skip to next iteration on failure

                aliceHandle = aliceRes.Unwrap();

                // Bob
                var bobRes = bobMat.CalculateSharedSecretAsRecipient(aliceMat.IdentityX25519PublicKey, aliceEphPub,
                    bobOpkId, info); // Pass nullable ID
                if (bobRes.IsErr)
                {
                    _output.WriteLine($"[Loop Iteration {i + 1}] Bob Error: {bobRes.UnwrapErr()}");
                    continue;
                } // Skip to next iteration on failure

                bobHandle = bobRes.Unwrap();

                // Compare
                iterationSuccess = CompareSecrets(aliceHandle, bobHandle);
                if (!iterationSuccess)
                {
                    _output.WriteLine($"[Loop Iteration {i + 1}] SECRET MISMATCH!");
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine($"[Loop Iteration {i + 1}] UNEXPECTED EXCEPTION: {ex.Message}");
                iterationSuccess = false; // Mark as failure
            }
            finally
            {
                aliceHandle?.Dispose();
                bobHandle?.Dispose();
                if (iterationSuccess) successCount++;
            }
            // Optional: Add a small delay or GC nudge if suspecting resource contention, but likely not needed
            // System.Threading.Thread.Sleep(5);
        }

        _output.WriteLine($"[Test: Loop_100_Pairs] Finished. Success Rate: {successCount}/{iterations}");
        Assert.Equal(iterations, successCount); // Assert that all iterations succeeded
    }
}