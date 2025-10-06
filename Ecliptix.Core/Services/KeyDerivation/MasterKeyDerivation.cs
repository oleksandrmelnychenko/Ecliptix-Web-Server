using System.Text;
using System.Security.Cryptography;
using Google.Protobuf;
using Ecliptix.Utilities;
using Konscious.Security.Cryptography;
using Ecliptix.Utilities.Failures.Sodium;

namespace Ecliptix.Core.Services.KeyDerivation;

public static class MasterKeyDerivation
{
    private const int KEY_SIZE = 32;
    private const int ARGON2_ITERATIONS = 4;
    private const int ARGON2_MEMORY_SIZE = 262144; // 256MB
    private const int ARGON2_PARALLELISM = 4;
    private const int CURRENT_VERSION = 1;

    private const string MASTER_SALT = "ECLIPTIX_MSTR_V1";
    private const string DOMAIN_CONTEXT = "ECLIPTIX_MASTER_KEY";
    private const string ED25519_CONTEXT = "ED25519";
    private const string X25519_CONTEXT = "X25519";
    private const string SPK_X25519_CONTEXT = "SPK_X25519";

    public static byte[] DeriveMasterKey(byte[] exportKey, ByteString membershipId)
    {
        Span<byte> membershipBytes = membershipId.Length <= 256
            ? stackalloc byte[membershipId.Length]
            : new byte[membershipId.Length];

        byte[] membershipArray = membershipId.ToByteArray();
        membershipArray.CopyTo(membershipBytes);

        Span<byte> versionBytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(versionBytes, CURRENT_VERSION);

        ReadOnlySpan<byte> domainBytes = Encoding.UTF8.GetBytes(DOMAIN_CONTEXT);

        byte[] argonSalt = CreateArgonSalt(membershipBytes, versionBytes, domainBytes);
        byte[]? stretchedKey = null;

        ReadOnlySpan<byte> masterSaltBytes = Encoding.UTF8.GetBytes(MASTER_SALT);

        try
        {
            stretchedKey = DeriveWithArgon2Id(exportKey, argonSalt);

            // Log Argon2id stretched key fingerprint for verification
            string stretchedKeyFingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stretchedKey))[..16];
            Serilog.Log.Information("[SERVER-ARGON2ID] Argon2id stretched key derived. StretchedKeyFingerprint: {StretchedKeyFingerprint}", stretchedKeyFingerprint);

            // Prepare Blake2b salt and personal parameters (must be exactly 16 bytes each)
            byte[] salt16 = masterSaltBytes.ToArray();
            byte[] personal16 = membershipBytes.ToArray();

            // Validate parameter lengths for Blake2b
            if (salt16.Length != 16)
            {
                // Truncate or pad salt to exactly 16 bytes
                byte[] adjustedSalt = new byte[16];
                int copyLength = Math.Min(salt16.Length, 16);
                Array.Copy(salt16, 0, adjustedSalt, 0, copyLength);
                salt16 = adjustedSalt;
                Serilog.Log.Warning("[SERVER-BLAKE2B-SALT] Salt adjusted to 16 bytes. Original length: {OriginalLength}", masterSaltBytes.Length);
            }

            if (personal16.Length != 16)
            {
                throw new InvalidOperationException($"Personal parameter (membershipId) must be exactly 16 bytes, got {personal16.Length}");
            }

            // Log Blake2b input parameters
            string saltHex = Convert.ToHexString(salt16)[..16];
            string personalHex = Convert.ToHexString(personal16)[..16];
            Serilog.Log.Information("[SERVER-BLAKE2B-INPUT] Blake2b inputs. SaltLength: {SaltLength}, PersonalLength: {PersonalLength}, SaltPrefix: {SaltPrefix}, PersonalPrefix: {PersonalPrefix}",
                salt16.Length, personal16.Length, saltHex, personalHex);

            Result<byte[], SodiumFailure> hashResult = SodiumInterop.Blake2bHashSaltPersonal(
                message: stretchedKey,
                key: null,
                salt: salt16,
                personal: personal16,
                outputSize: KEY_SIZE
            );

            if (hashResult.IsErr)
                throw new InvalidOperationException($"Blake2b hash failed: {hashResult.UnwrapErr().Message}");

            byte[] masterKey = hashResult.Unwrap();

            // Log master key fingerprint immediately after Blake2b
            string masterKeyFingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(masterKey))[..16];
            Serilog.Log.Information("[SERVER-BLAKE2B-OUTPUT] Master key derived from Blake2b. MasterKeyFingerprint: {MasterKeyFingerprint}", masterKeyFingerprint);

            return masterKey;
        }
        finally
        {
            if (stretchedKey != null)
                CryptographicOperations.ZeroMemory(stretchedKey);

            CryptographicOperations.ZeroMemory(argonSalt);
            CryptographicOperations.ZeroMemory(membershipArray);
            CryptographicOperations.ZeroMemory(membershipBytes);
            CryptographicOperations.ZeroMemory(versionBytes);
        }
    }

    public static Result<SodiumSecureMemoryHandle, SodiumFailure> DeriveMasterKeyHandle(
        SodiumSecureMemoryHandle exportKeyHandle, ByteString membershipId)
    {
        byte[]? exportKeyBytes = null;
        byte[]? stretchedKey = null;
        byte[]? argonSalt = null;

        try
        {
            Result<byte[], SodiumFailure> readResult = exportKeyHandle.ReadBytes(64);
            if (readResult.IsErr)
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(readResult.UnwrapErr());
            exportKeyBytes = readResult.Unwrap();

            Span<byte> membershipBytes = membershipId.Length <= 256
                ? stackalloc byte[membershipId.Length]
                : new byte[membershipId.Length];

            byte[] membershipArray = membershipId.ToByteArray();
            membershipArray.CopyTo(membershipBytes);

            Span<byte> versionBytes = stackalloc byte[sizeof(int)];
            BitConverter.TryWriteBytes(versionBytes, CURRENT_VERSION);

            ReadOnlySpan<byte> domainBytes = Encoding.UTF8.GetBytes(DOMAIN_CONTEXT);

            argonSalt = CreateArgonSalt(membershipBytes, versionBytes, domainBytes);

            ReadOnlySpan<byte> masterSaltBytes = Encoding.UTF8.GetBytes(MASTER_SALT);

            // Log Argon2id salt for verification
            string argonSaltHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(argonSalt))[..16];
            Serilog.Log.Information("[SERVER-ARGON2ID-SALT] Argon2id salt created. ArgonSaltHash: {ArgonSaltHash}, MembershipIdLength: {MembershipIdLength}",
                argonSaltHash, membershipBytes.Length);

            stretchedKey = DeriveWithArgon2Id(exportKeyBytes, argonSalt);

            // Log Argon2id stretched key fingerprint for verification
            string stretchedKeyFingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stretchedKey))[..16];
            Serilog.Log.Information("[SERVER-ARGON2ID-HANDLE] Argon2id stretched key derived. StretchedKeyFingerprint: {StretchedKeyFingerprint}", stretchedKeyFingerprint);

            // Prepare Blake2b salt and personal parameters (must be exactly 16 bytes each)
            byte[] salt16 = masterSaltBytes.ToArray();
            byte[] personal16 = membershipBytes.ToArray();

            // Validate parameter lengths for Blake2b
            if (salt16.Length != 16)
            {
                // Truncate or pad salt to exactly 16 bytes
                byte[] adjustedSalt = new byte[16];
                int copyLength = Math.Min(salt16.Length, 16);
                Array.Copy(salt16, 0, adjustedSalt, 0, copyLength);
                salt16 = adjustedSalt;
                Serilog.Log.Warning("[SERVER-BLAKE2B-SALT-HANDLE] Salt adjusted to 16 bytes. Original length: {OriginalLength}", masterSaltBytes.Length);
            }

            if (personal16.Length != 16)
            {
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                    SodiumFailure.InvalidOperation($"Personal parameter (membershipId) must be exactly 16 bytes, got {personal16.Length}"));
            }

            // Log Blake2b input parameters
            string saltHex = Convert.ToHexString(salt16)[..16];
            string personalHex = Convert.ToHexString(personal16)[..16];
            Serilog.Log.Information("[SERVER-BLAKE2B-INPUT-HANDLE] Blake2b inputs. SaltLength: {SaltLength}, PersonalLength: {PersonalLength}, SaltPrefix: {SaltPrefix}, PersonalPrefix: {PersonalPrefix}",
                salt16.Length, personal16.Length, saltHex, personalHex);

            Result<byte[], SodiumFailure> hashResult = SodiumInterop.Blake2bHashSaltPersonal(
                message: stretchedKey,
                key: null,
                salt: salt16,
                personal: personal16,
                outputSize: KEY_SIZE
            );

            if (hashResult.IsErr)
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(hashResult.UnwrapErr());

            byte[] masterKeyBytes = hashResult.Unwrap();

            // Log master key fingerprint immediately after Blake2b
            string masterKeyFingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(masterKeyBytes))[..16];
            Serilog.Log.Information("[SERVER-BLAKE2B-OUTPUT-HANDLE] Master key derived from Blake2b. MasterKeyFingerprint: {MasterKeyFingerprint}", masterKeyFingerprint);

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult = SodiumSecureMemoryHandle.Allocate(KEY_SIZE);
            if (allocResult.IsErr)
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
                return allocResult;
            }

            SodiumSecureMemoryHandle masterKeyHandle = allocResult.Unwrap();
            Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(masterKeyBytes);
            CryptographicOperations.ZeroMemory(masterKeyBytes);

            if (writeResult.IsErr)
            {
                masterKeyHandle.Dispose();
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(writeResult.UnwrapErr());
            }

            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(
                SodiumFailure.InvalidOperation($"Failed to derive master key: {ex.Message}"));
        }
        finally
        {
            if (exportKeyBytes != null)
                CryptographicOperations.ZeroMemory(exportKeyBytes);
            if (stretchedKey != null)
                CryptographicOperations.ZeroMemory(stretchedKey);
            if (argonSalt != null)
                CryptographicOperations.ZeroMemory(argonSalt);
        }
    }

    private static byte[] CreateArgonSalt(ReadOnlySpan<byte> membershipBytes, ReadOnlySpan<byte> versionBytes,
        ReadOnlySpan<byte> domainBytes)
    {
        int totalLength = membershipBytes.Length + versionBytes.Length + domainBytes.Length;

        Span<byte> combinedInput = totalLength <= 512
            ? stackalloc byte[totalLength]
            : new byte[totalLength];

        try
        {
            int offset = 0;
            membershipBytes.CopyTo(combinedInput[offset..]);
            offset += membershipBytes.Length;

            versionBytes.CopyTo(combinedInput[offset..]);
            offset += versionBytes.Length;

            domainBytes.CopyTo(combinedInput[offset..]);

            byte[] salt = ComputeHashFromSpan(combinedInput);

            return salt;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(combinedInput);
        }
    }

    private static byte[] DeriveWithArgon2Id(byte[] exportKey, byte[] salt)
    {
        using Argon2id argon2 = new(exportKey)
        {
            Salt = salt,
            DegreeOfParallelism = ARGON2_PARALLELISM,
            Iterations = ARGON2_ITERATIONS,
            MemorySize = ARGON2_MEMORY_SIZE
        };

        return argon2.GetBytes(KEY_SIZE);
    }

    public static byte[] DeriveEd25519Seed(byte[] masterKey, string membershipId)
    {
        Span<byte> versionBytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(versionBytes, CURRENT_VERSION);

        ReadOnlySpan<byte> contextBytes = Encoding.UTF8.GetBytes(ED25519_CONTEXT);

        int memberBytesLength = Encoding.UTF8.GetByteCount(membershipId);
        Span<byte> memberBytes = memberBytesLength <= 256
            ? stackalloc byte[memberBytesLength]
            : new byte[memberBytesLength];
        Encoding.UTF8.GetBytes(membershipId, memberBytes);

        int totalLength = versionBytes.Length + contextBytes.Length + memberBytes.Length;
        Span<byte> combinedContext = totalLength <= 512
            ? stackalloc byte[totalLength]
            : new byte[totalLength];

        try
        {
            int offset = 0;
            versionBytes.CopyTo(combinedContext[offset..]);
            offset += versionBytes.Length;

            contextBytes.CopyTo(combinedContext[offset..]);
            offset += contextBytes.Length;

            memberBytes.CopyTo(combinedContext[offset..]);

            return HashWithGenericHashFromSpan(masterKey, combinedContext, KEY_SIZE);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(versionBytes);
            CryptographicOperations.ZeroMemory(memberBytes);
            CryptographicOperations.ZeroMemory(combinedContext);
        }
    }

    public static byte[] DeriveX25519Seed(byte[] masterKey, string membershipId)
    {
        Span<byte> versionBytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(versionBytes, CURRENT_VERSION);

        ReadOnlySpan<byte> contextBytes = Encoding.UTF8.GetBytes(X25519_CONTEXT);

        int memberBytesLength = Encoding.UTF8.GetByteCount(membershipId);
        Span<byte> memberBytes = memberBytesLength <= 256
            ? stackalloc byte[memberBytesLength]
            : new byte[memberBytesLength];
        Encoding.UTF8.GetBytes(membershipId, memberBytes);

        int totalLength = versionBytes.Length + contextBytes.Length + memberBytes.Length;
        Span<byte> combinedContext = totalLength <= 512
            ? stackalloc byte[totalLength]
            : new byte[totalLength];

        try
        {
            int offset = 0;
            versionBytes.CopyTo(combinedContext[offset..]);
            offset += versionBytes.Length;

            contextBytes.CopyTo(combinedContext[offset..]);
            offset += contextBytes.Length;

            memberBytes.CopyTo(combinedContext[offset..]);

            return HashWithGenericHashFromSpan(masterKey, combinedContext, KEY_SIZE);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(versionBytes);
            CryptographicOperations.ZeroMemory(memberBytes);
            CryptographicOperations.ZeroMemory(combinedContext);
        }
    }

    public static byte[] DeriveSignedPreKeySeed(byte[] masterKey, string membershipId)
    {
        Span<byte> versionBytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(versionBytes, CURRENT_VERSION);

        ReadOnlySpan<byte> contextBytes = Encoding.UTF8.GetBytes(SPK_X25519_CONTEXT);

        int memberBytesLength = Encoding.UTF8.GetByteCount(membershipId);
        Span<byte> memberBytes = memberBytesLength <= 256
            ? stackalloc byte[memberBytesLength]
            : new byte[memberBytesLength];
        Encoding.UTF8.GetBytes(membershipId, memberBytes);

        int totalLength = versionBytes.Length + contextBytes.Length + memberBytes.Length;
        Span<byte> combinedContext = totalLength <= 512
            ? stackalloc byte[totalLength]
            : new byte[totalLength];

        try
        {
            int offset = 0;
            versionBytes.CopyTo(combinedContext[offset..]);
            offset += versionBytes.Length;

            contextBytes.CopyTo(combinedContext[offset..]);
            offset += contextBytes.Length;

            memberBytes.CopyTo(combinedContext[offset..]);

            return HashWithGenericHashFromSpan(masterKey, combinedContext, KEY_SIZE);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(versionBytes);
            CryptographicOperations.ZeroMemory(memberBytes);
            CryptographicOperations.ZeroMemory(combinedContext);
        }
    }

    private static byte[] ComputeHashFromSpan(ReadOnlySpan<byte> data)
    {
        return SHA256.HashData(data.ToArray());
    }

    private static byte[] HashWithGenericHashFromSpan(byte[] key, ReadOnlySpan<byte> data, int outputSize)
    {
        Result<byte[], SodiumFailure> hashResult = SodiumInterop.Blake2bHash(data.ToArray(), key, outputSize);
        if (hashResult.IsErr)
            throw new InvalidOperationException($"Blake2b hash failed: {hashResult.UnwrapErr().Message}");

        return hashResult.Unwrap();
    }
}