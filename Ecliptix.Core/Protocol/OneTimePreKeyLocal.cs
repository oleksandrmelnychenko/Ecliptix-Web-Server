using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

// OneTimePreKeyLocal now manages a secure handle for its private key
public readonly struct OneTimePreKeyLocal : IDisposable // Now needs to be disposable
{
    public readonly uint PreKeyId;
    public readonly SodiumSecureMemoryHandle PrivateKeyHandle; // Changed from byte[]
    public readonly byte[] PublicKey; // Public key remains byte[]

    // Internal constructor takes the handle
    internal OneTimePreKeyLocal(uint preKeyId, SodiumSecureMemoryHandle privateKeyHandle, byte[] publicKey)
    {
        // Basic validation
        if (privateKeyHandle == null || privateKeyHandle.IsInvalid ||
            privateKeyHandle.Length != Constants.X25519PrivateKeySize)
            throw new ArgumentException("Invalid private key handle", nameof(privateKeyHandle));
        if (publicKey is not { Length: Constants.X25519PublicKeySize })
            throw new ArgumentException("Invalid public key size", nameof(publicKey));

        PreKeyId = preKeyId;
        PrivateKeyHandle = privateKeyHandle;
        PublicKey = publicKey;
    }

    public static Result<OneTimePreKeyLocal, ShieldError> Generate(uint preKeyId)
    {
        SodiumSecureMemoryHandle? securePrivateKey = null;
        byte[]? tempPrivateKeyBytes = null;

        try
        {
            SodiumCore.Init();

            // 1. Allocate secure memory
            securePrivateKey = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);

            // 2. Generate random bytes into a *temporary* managed buffer
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);

            // 3. Copy temporary bytes into secure memory
            securePrivateKey.Write(tempPrivateKeyBytes);

            // 4. IMMEDIATELY WIPE temporary buffer
            SodiumInterop.SecureWipe(tempPrivateKeyBytes); // Use P/Invoke helper for byte[]
            tempPrivateKeyBytes = null; // Release reference

            // 5. Generate public key using data from secure memory handle
            // WARNING: GetSpan exposes raw pointer. Use carefully or copy out.
            // Using GetSpan requires unsafe context or careful lifetime management.
            // Safer alternative: copy out temporarily.
            byte[] tempPrivKeyCopy = new byte[Constants.X25519PrivateKeySize];
            securePrivateKey.Read(tempPrivKeyCopy); // Copy out
            byte[] publicKeyBytes = ScalarMult.Base(tempPrivKeyCopy); // Use the copy
            SodiumInterop.SecureWipe(tempPrivKeyCopy); // Wipe the temporary copy

            // 6. Return struct with the secure handle
            return Result<OneTimePreKeyLocal, ShieldError>.Ok(
                new OneTimePreKeyLocal(preKeyId, securePrivateKey, publicKeyBytes)
            );
        }
        catch (Exception ex)
        {
            // If generation failed, ensure the secure handle (if allocated) is disposed
            securePrivateKey?.Dispose();
            // Also wipe any temporary buffer if it wasn't wiped yet (should be null normally here)
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes);

            return Result<OneTimePreKeyLocal, ShieldError>.Err(
                ShieldError.DeriveKey($"Failed OPK Gen ID {preKeyId}.", ex)
            );
        }
    }

    // Implement IDisposable to dispose the handle
    public void Dispose()
    {
        PrivateKeyHandle?.Dispose();
    }
}