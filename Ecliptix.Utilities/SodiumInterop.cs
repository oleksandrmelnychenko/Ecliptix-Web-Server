using System.Runtime.InteropServices;
using Ecliptix.Utilities.Failures.Sodium;

namespace Ecliptix.Utilities;

public static class SodiumInterop
{
    private const string LibSodium = "libsodium";
    private const int MaxBufferSize = 1_000_000_000;
    private const int SmallBufferThreshold = 64;

    private static readonly Result<Unit, SodiumFailure> InitializationResult;

    static SodiumInterop()
    {
        InitializationResult = InitializeSodium();
    }

    public static bool IsInitialized => InitializationResult.IsOk;

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    private static extern int sodium_init();

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern IntPtr sodium_malloc(UIntPtr size);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal static extern void sodium_free(IntPtr ptr);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void sodium_memzero(IntPtr ptr, UIntPtr length);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sodium_memcmp(in byte b1, in byte b2, UIntPtr length);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_generichash(
        byte[] output, UIntPtr outlen,
        byte[] input, ulong inlen,
        byte[]? key, UIntPtr keylen);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_generichash_blake2b_salt_personal(
        byte[] output, UIntPtr outlen,
        byte[] input, ulong inlen,
        byte[]? key, UIntPtr keylen,
        byte[] salt,
        byte[] personal);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void randombytes_buf(byte[] buffer, UIntPtr size);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_scalarmult_base(byte[] q, byte[] n);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_scalarmult(byte[] q, byte[] n, byte[] p);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_sign_keypair(byte[] pk, byte[] sk);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_sign_seed_keypair(byte[] pk, byte[] sk, byte[] seed);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_sign_detached(
        byte[] sig, out ulong siglen_p,
        byte[] m, ulong mlen,
        byte[] sk);

    [DllImport(LibSodium, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int crypto_sign_verify_detached(
        byte[] sig,
        byte[] m, ulong mlen,
        byte[] pk);

    private const int crypto_generichash_BYTES = 32;
    private const int crypto_generichash_SALTBYTES = 16;
    private const int crypto_generichash_PERSONALBYTES = 16;
    private const int crypto_scalarmult_BYTES = 32;
    private const int crypto_scalarmult_SCALARBYTES = 32;
    private const int crypto_sign_PUBLICKEYBYTES = 32;
    private const int crypto_sign_SECRETKEYBYTES = 64;
    private const int crypto_sign_SEEDBYTES = 32;
    private const int crypto_sign_BYTES = 64;

    private static Result<Unit, SodiumFailure> InitializeSodium()
    {
        return Result<Unit, SodiumFailure>.Try(
            () =>
            {
                int result = sodium_init();
                const int dllImportSuccess = 0;
                if (result < dllImportSuccess)
                    throw new InvalidOperationException("sodium_init returned error");
            },
            ex => ex switch
            {
                DllNotFoundException dllEx => SodiumFailure.LibraryNotFound(
                    string.Format(SodiumFailureMessages.LibraryLoadFailed, LibSodium), dllEx),
                InvalidOperationException opEx when opEx.Message.Contains("sodium_init") =>
                    SodiumFailure.InitializationFailed("Initialization failed", opEx),
                _ => SodiumFailure.InitializationFailed("Unexpected initialization error", ex)
            }
        );
    }

    public static Result<Unit, SodiumFailure> SecureWipe(byte[]? buffer)
    {
        if (!IsInitialized)
            return Result<Unit, SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        return Result<byte[], SodiumFailure>
            .FromValue(buffer, SodiumFailure.BufferTooSmall("Buffer cannot be null"))
            .Bind(nonNullBuffer => nonNullBuffer switch
            {
                { Length: 0 } => Result<Unit, SodiumFailure>.Ok(Unit.Value),
                _ => Result<byte[], SodiumFailure>.Validate(
                        nonNullBuffer,
                        buf => buf.Length <= MaxBufferSize,
                        SodiumFailure.BufferTooLarge(
                            string.Format(SodiumFailureMessages.BufferTooLarge, nonNullBuffer.Length, MaxBufferSize)))
                    .Bind(validBuffer => validBuffer.Length <= SmallBufferThreshold
                        ? WipeSmallBuffer(validBuffer)
                        : WipeLargeBuffer(validBuffer))
            });
    }

    public static Result<bool, SodiumFailure> ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
        {
            return Result<bool, SodiumFailure>.Ok(false);
        }

        if (a.IsEmpty)
        {
            return Result<bool, SodiumFailure>.Ok(true);
        }

        try
        {
            unsafe
            {
                fixed (byte* pA = a)
                fixed (byte* pB = b)
                {
                    int result = sodium_memcmp(in *pA, in *pB, (UIntPtr)a.Length);
                    return Result<bool, SodiumFailure>.Ok(result == 0);
                }
            }
        }
        catch (Exception ex)
        {
            return Result<bool, SodiumFailure>.Err(
                SodiumFailure.ComparisonFailed("libsodium constant-time comparison failed.", ex));
        }
    }

    private static Result<Unit, SodiumFailure> WipeSmallBuffer(byte[] buffer)
    {
        return Result<Unit, SodiumFailure>.Try(
            () => { Array.Clear(buffer, 0, buffer.Length); },
            ex =>
                SodiumFailure.SecureWipeFailed(
                    string.Format(SodiumFailureMessages.SmallBufferClearFailed, buffer.Length), ex));
    }

    private static Result<Unit, SodiumFailure> WipeLargeBuffer(byte[] buffer)
    {
        GCHandle handle = default;
        return Result<Unit, SodiumFailure>.Try(
            () =>
            {
                handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                IntPtr ptr = handle.AddrOfPinnedObject();
                if (ptr == IntPtr.Zero && buffer.Length > 0)
                    throw new InvalidOperationException(SodiumFailureMessages.AddressOfPinnedObjectFailed);

                sodium_memzero(ptr, (UIntPtr)buffer.Length);
            },
            ex => ex switch
            {
                ArgumentException argEx => SodiumFailure.MemoryPinningFailed(
                    SodiumFailureMessages.PinningFailed, argEx),
                OutOfMemoryException oomEx => SodiumFailure.MemoryPinningFailed(
                    SodiumFailureMessages.InsufficientMemory, oomEx),
                InvalidOperationException opEx when opEx.Message.Contains(SodiumExceptionMessagePatterns
                        .AddressPinnedObjectPattern) =>
                    SodiumFailure.MemoryPinningFailed(SodiumFailureMessages.GetPinnedAddressFailed, opEx),
                _ => SodiumFailure.MemoryPinningFailed(
                    string.Format(SodiumFailureMessages.SecureWipeFailed, buffer.Length), ex)
            },
            () =>
            {
                if (handle.IsAllocated) handle.Free();
            }
        );
    }

    public static Result<byte[], SodiumFailure> Blake2bHash(
        byte[] message,
        byte[]? key = null,
        int outputSize = crypto_generichash_BYTES)
    {
        if (!IsInitialized)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (message == null || message.Length == 0)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter("Message cannot be null or empty"));

        if (outputSize <= 0 || outputSize > 64)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Output size must be between 1 and 64 bytes, got {outputSize}"));

        return Result<byte[], SodiumFailure>.Try(
            () =>
            {
                byte[] output = new byte[outputSize];

                int result = crypto_generichash(
                    output, (UIntPtr)outputSize,
                    message, (ulong)message.Length,
                    key, key != null ? (UIntPtr)key.Length : UIntPtr.Zero);

                if (result != 0)
                    throw new InvalidOperationException($"Blake2b hash failed with result code: {result}");

                return output;
            },
            ex => SodiumFailure.HashFailed($"Blake2b hash operation failed: {ex.Message}", ex));
    }

    public static Result<byte[], SodiumFailure> Blake2bHashSaltPersonal(
        byte[] message,
        byte[]? key,
        byte[] salt,
        byte[] personal,
        int outputSize = crypto_generichash_BYTES)
    {
        if (!IsInitialized)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (message == null || message.Length == 0)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter("Message cannot be null or empty"));

        if (salt == null || salt.Length != crypto_generichash_SALTBYTES)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Salt must be exactly {crypto_generichash_SALTBYTES} bytes, got {salt?.Length ?? 0}"));

        if (personal == null || personal.Length != crypto_generichash_PERSONALBYTES)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Personal must be exactly {crypto_generichash_PERSONALBYTES} bytes, got {personal?.Length ?? 0}"));

        if (outputSize <= 0 || outputSize > 64)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Output size must be between 1 and 64 bytes, got {outputSize}"));

        return Result<byte[], SodiumFailure>.Try(
            () =>
            {
                byte[] output = new byte[outputSize];

                int result = crypto_generichash_blake2b_salt_personal(
                    output, (UIntPtr)outputSize,
                    message, (ulong)message.Length,
                    key, key != null ? (UIntPtr)key.Length : UIntPtr.Zero,
                    salt,
                    personal);

                if (result != 0)
                    throw new InvalidOperationException($"Blake2b salt/personal hash failed with result code: {result}");

                return output;
            },
            ex => SodiumFailure.HashFailed($"Blake2b salt/personal hash operation failed: {ex.Message}", ex));
    }

    public static Result<byte[], SodiumFailure> GetRandomBytes(int count)
    {
        if (!IsInitialized)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (count <= 0)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Count must be positive, got {count}"));

        return Result<byte[], SodiumFailure>.Try(
            () =>
            {
                byte[] buffer = new byte[count];
                randombytes_buf(buffer, (UIntPtr)count);
                return buffer;
            },
            ex => SodiumFailure.InvalidOperation($"Random bytes generation failed: {ex.Message}", ex));
    }

    public static Result<byte[], SodiumFailure> ScalarMultBase(byte[] secretKey)
    {
        if (!IsInitialized)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (secretKey == null || secretKey.Length != crypto_scalarmult_SCALARBYTES)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Secret key must be exactly {crypto_scalarmult_SCALARBYTES} bytes, got {secretKey?.Length ?? 0}"));

        return Result<byte[], SodiumFailure>.Try(
            () =>
            {
                byte[] publicKey = new byte[crypto_scalarmult_BYTES];
                int result = crypto_scalarmult_base(publicKey, secretKey);

                if (result != 0)
                    throw new InvalidOperationException($"ScalarMult.Base failed with result code: {result}");

                return publicKey;
            },
            ex => SodiumFailure.InvalidOperation($"Scalar multiplication (base) failed: {ex.Message}", ex));
    }

    public static Result<byte[], SodiumFailure> ScalarMult(byte[] secretKey, byte[] publicKey)
    {
        if (!IsInitialized)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (secretKey == null || secretKey.Length != crypto_scalarmult_SCALARBYTES)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Secret key must be exactly {crypto_scalarmult_SCALARBYTES} bytes, got {secretKey?.Length ?? 0}"));

        if (publicKey == null || publicKey.Length != crypto_scalarmult_BYTES)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Public key must be exactly {crypto_scalarmult_BYTES} bytes, got {publicKey?.Length ?? 0}"));

        return Result<byte[], SodiumFailure>.Try(
            () =>
            {
                byte[] sharedSecret = new byte[crypto_scalarmult_BYTES];
                int result = crypto_scalarmult(sharedSecret, secretKey, publicKey);

                if (result != 0)
                    throw new InvalidOperationException($"ScalarMult failed with result code: {result}");

                return sharedSecret;
            },
            ex => SodiumFailure.InvalidOperation($"Scalar multiplication failed: {ex.Message}", ex));
    }

    public static Result<(byte[] PublicKey, byte[] SecretKey), SodiumFailure> GenerateSigningKeyPair()
    {
        if (!IsInitialized)
            return Result<(byte[], byte[]), SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        return Result<(byte[], byte[]), SodiumFailure>.Try(
            () =>
            {
                byte[] publicKey = new byte[crypto_sign_PUBLICKEYBYTES];
                byte[] secretKey = new byte[crypto_sign_SECRETKEYBYTES];

                int result = crypto_sign_keypair(publicKey, secretKey);

                if (result != 0)
                    throw new InvalidOperationException($"Key pair generation failed with result code: {result}");

                return (publicKey, secretKey);
            },
            ex => SodiumFailure.InvalidOperation($"Signing key pair generation failed: {ex.Message}", ex));
    }

    public static Result<(byte[] PublicKey, byte[] SecretKey), SodiumFailure> GenerateSigningKeyPairFromSeed(byte[] seed)
    {
        if (!IsInitialized)
            return Result<(byte[], byte[]), SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (seed == null || seed.Length != crypto_sign_SEEDBYTES)
            return Result<(byte[], byte[]), SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Seed must be exactly {crypto_sign_SEEDBYTES} bytes, got {seed?.Length ?? 0}"));

        return Result<(byte[], byte[]), SodiumFailure>.Try(
            () =>
            {
                byte[] publicKey = new byte[crypto_sign_PUBLICKEYBYTES];
                byte[] secretKey = new byte[crypto_sign_SECRETKEYBYTES];

                int result = crypto_sign_seed_keypair(publicKey, secretKey, seed);

                if (result != 0)
                    throw new InvalidOperationException($"Deterministic key pair generation failed with result code: {result}");

                return (publicKey, secretKey);
            },
            ex => SodiumFailure.InvalidOperation($"Signing key pair generation from seed failed: {ex.Message}", ex));
    }

    public static Result<byte[], SodiumFailure> SignDetached(byte[] message, byte[] secretKey)
    {
        if (!IsInitialized)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (message == null || message.Length == 0)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter("Message cannot be null or empty"));

        if (secretKey == null || secretKey.Length != crypto_sign_SECRETKEYBYTES)
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Secret key must be exactly {crypto_sign_SECRETKEYBYTES} bytes, got {secretKey?.Length ?? 0}"));

        return Result<byte[], SodiumFailure>.Try(
            () =>
            {
                byte[] signature = new byte[crypto_sign_BYTES];
                ulong signatureLength;

                int result = crypto_sign_detached(
                    signature, out signatureLength,
                    message, (ulong)message.Length,
                    secretKey);

                if (result != 0)
                    throw new InvalidOperationException($"Signing failed with result code: {result}");

                return signature;
            },
            ex => SodiumFailure.InvalidOperation($"Detached signing failed: {ex.Message}", ex));
    }

    public static Result<bool, SodiumFailure> VerifyDetached(byte[] signature, byte[] message, byte[] publicKey)
    {
        if (!IsInitialized)
            return Result<bool, SodiumFailure>.Err(
                SodiumFailure.InitializationFailed("Sodium not initialized"));

        if (signature == null || signature.Length != crypto_sign_BYTES)
            return Result<bool, SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Signature must be exactly {crypto_sign_BYTES} bytes, got {signature?.Length ?? 0}"));

        if (message == null || message.Length == 0)
            return Result<bool, SodiumFailure>.Err(
                SodiumFailure.InvalidParameter("Message cannot be null or empty"));

        if (publicKey == null || publicKey.Length != crypto_sign_PUBLICKEYBYTES)
            return Result<bool, SodiumFailure>.Err(
                SodiumFailure.InvalidParameter($"Public key must be exactly {crypto_sign_PUBLICKEYBYTES} bytes, got {publicKey?.Length ?? 0}"));

        return Result<bool, SodiumFailure>.Try(
            () =>
            {
                int result = crypto_sign_verify_detached(
                    signature,
                    message, (ulong)message.Length,
                    publicKey);

                return result == 0;
            },
            ex => SodiumFailure.InvalidOperation($"Signature verification failed: {ex.Message}", ex));
    }

    public static Result<(SodiumSecureMemoryHandle SkHandle, byte[] Pk), EcliptixProtocolFailure> GenerateX25519KeyPair(string keyPurpose)
    {
        byte[]? secretKeyBytes = null;
        SodiumSecureMemoryHandle? skHandle = null;

        try
        {
            Result<byte[], SodiumFailure> randomResult = GetRandomBytes(crypto_scalarmult_SCALARBYTES);
            if (randomResult.IsErr)
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.KeyGeneration($"Failed to generate random bytes for {keyPurpose}: {randomResult.UnwrapErr().Message}"));
            secretKeyBytes = randomResult.Unwrap();

            Result<byte[], SodiumFailure> publicKeyResult = ScalarMultBase(secretKeyBytes);
            if (publicKeyResult.IsErr)
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.KeyGeneration($"Failed to derive public key for {keyPurpose}: {publicKeyResult.UnwrapErr().Message}"));
            byte[] publicKey = publicKeyResult.Unwrap();

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(crypto_scalarmult_SCALARBYTES);
            if (allocResult.IsErr)
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to allocate secure memory for {keyPurpose}: {allocResult.UnwrapErr().Message}"));
            skHandle = allocResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = skHandle.Write(secretKeyBytes);
            if (writeResult.IsErr)
            {
                skHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to write secret key to secure memory for {keyPurpose}: {writeResult.UnwrapErr().Message}"));
            }

            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((skHandle, publicKey));
        }
        catch (Exception ex)
        {
            skHandle?.Dispose();
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.KeyGeneration($"Unexpected error generating X25519 key pair for {keyPurpose}", ex));
        }
        finally
        {
            if (secretKeyBytes != null)
                SecureWipe(secretKeyBytes).IgnoreResult();
        }
    }
}