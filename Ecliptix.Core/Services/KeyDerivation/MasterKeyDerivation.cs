using System.Text;
using System.Security.Cryptography;
using Google.Protobuf;
using Ecliptix.Utilities;
using Konscious.Security.Cryptography;
using Ecliptix.Utilities.Failures.Sodium;
using Serilog;

namespace Ecliptix.Core.Services.KeyDerivation;

public static class MasterKeyDerivation
{
    private const int KeySize = 32;
    private const int Argon2Iterations = 4;
    private const int Argon2MemorySize = 262144;
    private const int Argon2Parallelism = 4;
    private const int CurrentVersion = 1;
    private const int ExportKeySize = 64;

    private const string MasterSalt = "ECLIPTIX_MSTR_V1";
    private const string DomainContext = "ECLIPTIX_MASTER_KEY";
    private const string Ed25519Context = "ED25519";
    private const string X25519Context = "X25519";
    private const string SpkX25519Context = "SPK_X25519";

    private const string ServerArgon2IdLogTag = "[SERVER-ARGON2ID]";
    private const string ServerArgon2IdSaltLogTag = "[SERVER-ARGON2ID-SALT]";
    private const string ServerArgon2IdHandleLogTag = "[SERVER-ARGON2ID-HANDLE]";
    private const string ServerBlake2BInputLogTag = "[SERVER-BLAKE2B-INPUT]";
    private const string ServerBlake2BInputHandleLogTag = "[SERVER-BLAKE2B-INPUT-HANDLE]";
    private const string ServerBlake2BOutputLogTag = "[SERVER-BLAKE2B-OUTPUT]";
    private const string ServerBlake2BOutputHandleLogTag = "[SERVER-BLAKE2B-OUTPUT-HANDLE]";
    private const string ServerBlake2BSaltLogTag = "[SERVER-BLAKE2B-SALT]";
    private const string ServerBlake2BSaltHandleLogTag = "[SERVER-BLAKE2B-SALT-HANDLE]";

    private const string Argon2IdLogMessage =
        "{LogTag} Argon2id stretched key derived. StretchedKeyFingerprint: {StretchedKeyFingerprint}";

    private const string Argon2IdSaltLogMessage =
        "{LogTag} Argon2id salt created. ArgonSaltHash: {ArgonSaltHash}, MembershipIdLength: {MembershipIdLength}";

    private const string Blake2BInputLogMessage =
        "{LogTag} Blake2b inputs. SaltLength: {SaltLength}, PersonalLength: {PersonalLength}, SaltPrefix: {SaltPrefix}, PersonalPrefix: {PersonalPrefix}";

    private const string Blake2BOutputLogMessage =
        "{LogTag} Master key derived from Blake2b. MasterKeyFingerprint: {MasterKeyFingerprint}";

    private const string Blake2BSaltAdjustedWarning =
        "{LogTag} Salt adjusted to {RequiredSize} bytes. Original length: {OriginalLength}";

    private const string Blake2BHashFailedMessage = "Blake2b hash failed: {0}";
    private const string MasterKeyDerivationFailedMessage = "Failed to derive master key: {0}";

    private const string PersonalParameterSizeMismatchMessage =
        "Personal parameter (membershipId) must be exactly {0} bytes, got {1}";

    public static byte[] DeriveMasterKey(byte[] exportKey, ByteString membershipId)
    {
        Span<byte> membershipBytes = membershipId.Length <= SharedConstants.StackAllocationThreshold
            ? stackalloc byte[membershipId.Length]
            : new byte[membershipId.Length];

        byte[] membershipArray = membershipId.ToByteArray();
        membershipArray.CopyTo(membershipBytes);

        Span<byte> versionBytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(versionBytes, CurrentVersion);

        ReadOnlySpan<byte> domainBytes = Encoding.UTF8.GetBytes(DomainContext);

        byte[] argonSalt = CreateArgonSalt(membershipBytes, versionBytes, domainBytes);
        byte[]? stretchedKey = null;

        ReadOnlySpan<byte> masterSaltBytes = Encoding.UTF8.GetBytes(MasterSalt);

        try
        {
            stretchedKey = DeriveWithArgon2Id(exportKey, argonSalt);

            string stretchedKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(stretchedKey);
            Log.Information(Argon2IdLogMessage, ServerArgon2IdLogTag, stretchedKeyFingerprint);

            byte[] salt16 = AdjustBlake2BSaltParameter(masterSaltBytes, ServerBlake2BSaltLogTag);
            byte[] personal16 = ValidateBlake2BPersonalParameter(membershipBytes);

            string saltHex = CryptoHelpers.ComputeSha256Fingerprint(salt16);
            string personalHex = CryptoHelpers.ComputeSha256Fingerprint(personal16);
            Log.Information(Blake2BInputLogMessage, ServerBlake2BInputLogTag,
                salt16.Length, personal16.Length, saltHex, personalHex);

            Result<byte[], SodiumFailure> hashResult = SodiumInterop.Blake2bHashSaltPersonal(
                message: stretchedKey,
                key: null,
                salt: salt16,
                personal: personal16,
                outputSize: KeySize
            );

            if (hashResult.IsErr)
            {
                throw new InvalidOperationException(string.Format(Blake2BHashFailedMessage,
                    hashResult.UnwrapErr().Message));
            }

            byte[] masterKey = hashResult.Unwrap();

            string masterKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(masterKey);
            Log.Information(Blake2BOutputLogMessage, ServerBlake2BOutputLogTag, masterKeyFingerprint);

            return masterKey;
        }
        finally
        {
            if (stretchedKey != null)
            {
                CryptographicOperations.ZeroMemory(stretchedKey);
            }

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
            Result<byte[], SodiumFailure> readResult = exportKeyHandle.ReadBytes(ExportKeySize);
            if (readResult.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(readResult.UnwrapErr());
            }

            exportKeyBytes = readResult.Unwrap();

            Span<byte> membershipBytes = membershipId.Length <= SharedConstants.StackAllocationThreshold
                ? stackalloc byte[membershipId.Length]
                : new byte[membershipId.Length];

            byte[] membershipArray = membershipId.ToByteArray();
            membershipArray.CopyTo(membershipBytes);

            Span<byte> versionBytes = stackalloc byte[sizeof(int)];
            BitConverter.TryWriteBytes(versionBytes, CurrentVersion);

            ReadOnlySpan<byte> domainBytes = Encoding.UTF8.GetBytes(DomainContext);

            argonSalt = CreateArgonSalt(membershipBytes, versionBytes, domainBytes);

            ReadOnlySpan<byte> masterSaltBytes = Encoding.UTF8.GetBytes(MasterSalt);

            string argonSaltHash = CryptoHelpers.ComputeSha256Fingerprint(argonSalt);
            Log.Information(Argon2IdSaltLogMessage, ServerArgon2IdSaltLogTag,
                argonSaltHash, membershipBytes.Length);

            stretchedKey = DeriveWithArgon2Id(exportKeyBytes, argonSalt);

            string stretchedKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(stretchedKey);
            Log.Information(Argon2IdLogMessage, ServerArgon2IdHandleLogTag, stretchedKeyFingerprint);

            byte[] salt16 = AdjustBlake2BSaltParameter(masterSaltBytes, ServerBlake2BSaltHandleLogTag);
            Result<byte[], SodiumFailure> personalResult = TryValidateBlake2BPersonalParameter(membershipBytes);
            if (personalResult.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(personalResult.UnwrapErr());
            }

            byte[] personal16 = personalResult.Unwrap();

            string saltHex = CryptoHelpers.ComputeSha256Fingerprint(salt16);
            string personalHex = CryptoHelpers.ComputeSha256Fingerprint(personal16);
            Log.Information(Blake2BInputLogMessage, ServerBlake2BInputHandleLogTag,
                salt16.Length, personal16.Length, saltHex, personalHex);

            Result<byte[], SodiumFailure> hashResult = SodiumInterop.Blake2bHashSaltPersonal(
                message: stretchedKey,
                key: null,
                salt: salt16,
                personal: personal16,
                outputSize: KeySize
            );

            if (hashResult.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, SodiumFailure>.Err(hashResult.UnwrapErr());
            }

            byte[] masterKeyBytes = hashResult.Unwrap();

            string masterKeyFingerprint = CryptoHelpers.ComputeSha256Fingerprint(masterKeyBytes);
            Log.Information(Blake2BOutputLogMessage, ServerBlake2BOutputHandleLogTag, masterKeyFingerprint);

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult = SodiumSecureMemoryHandle.Allocate(KeySize);
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
                SodiumFailure.InvalidOperation(string.Format(MasterKeyDerivationFailedMessage, ex.Message)));
        }
        finally
        {
            if (exportKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(exportKeyBytes);
            }

            if (stretchedKey != null)
            {
                CryptographicOperations.ZeroMemory(stretchedKey);
            }

            if (argonSalt != null)
            {
                CryptographicOperations.ZeroMemory(argonSalt);
            }
        }
    }

    private static byte[] AdjustBlake2BSaltParameter(ReadOnlySpan<byte> saltBytes, string logTag)
    {
        byte[] salt16 = saltBytes.ToArray();

        if (salt16.Length != SharedConstants.Blake2bSaltSize)
        {
            byte[] adjustedSalt = new byte[SharedConstants.Blake2bSaltSize];
            int copyLength = Math.Min(salt16.Length, SharedConstants.Blake2bSaltSize);
            Array.Copy(salt16, 0, adjustedSalt, 0, copyLength);
            salt16 = adjustedSalt;
            Log.Warning(Blake2BSaltAdjustedWarning, logTag,
                SharedConstants.Blake2bSaltSize, saltBytes.Length);
        }

        return salt16;
    }

    private static byte[] ValidateBlake2BPersonalParameter(ReadOnlySpan<byte> personalBytes)
    {
        byte[] personal16 = personalBytes.ToArray();

        if (personal16.Length != SharedConstants.Blake2bPersonalSize)
        {
            throw new InvalidOperationException(string.Format(PersonalParameterSizeMismatchMessage,
                SharedConstants.Blake2bPersonalSize, personal16.Length));
        }

        return personal16;
    }

    private static Result<byte[], SodiumFailure> TryValidateBlake2BPersonalParameter(ReadOnlySpan<byte> personalBytes)
    {
        byte[] personal16 = personalBytes.ToArray();

        if (personal16.Length != SharedConstants.Blake2bPersonalSize)
        {
            return Result<byte[], SodiumFailure>.Err(
                SodiumFailure.InvalidOperation(string.Format(PersonalParameterSizeMismatchMessage,
                    SharedConstants.Blake2bPersonalSize, personal16.Length)));
        }

        return Result<byte[], SodiumFailure>.Ok(personal16);
    }

    private static byte[] CreateArgonSalt(ReadOnlySpan<byte> membershipBytes, ReadOnlySpan<byte> versionBytes,
        ReadOnlySpan<byte> domainBytes)
    {
        int totalLength = membershipBytes.Length + versionBytes.Length + domainBytes.Length;

        Span<byte> combinedInput = totalLength <= SharedConstants.LargeStackAllocationThreshold
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
            DegreeOfParallelism = Argon2Parallelism,
            Iterations = Argon2Iterations,
            MemorySize = Argon2MemorySize
        };

        return argon2.GetBytes(KeySize);
    }

    public static byte[] DeriveEd25519Seed(byte[] masterKey, string membershipId)
    {
        return DeriveSeedForContext(masterKey, membershipId, Ed25519Context);
    }

    public static byte[] DeriveX25519Seed(byte[] masterKey, string membershipId)
    {
        return DeriveSeedForContext(masterKey, membershipId, X25519Context);
    }

    public static byte[] DeriveSignedPreKeySeed(byte[] masterKey, string membershipId)
    {
        return DeriveSeedForContext(masterKey, membershipId, SpkX25519Context);
    }

    private static byte[] DeriveSeedForContext(byte[] masterKey, string membershipId, string context)
    {
        Span<byte> versionBytes = stackalloc byte[sizeof(int)];
        BitConverter.TryWriteBytes(versionBytes, CurrentVersion);

        ReadOnlySpan<byte> contextBytes = Encoding.UTF8.GetBytes(context);

        int memberBytesLength = Encoding.UTF8.GetByteCount(membershipId);
        Span<byte> memberBytes = memberBytesLength <= SharedConstants.StackAllocationThreshold
            ? stackalloc byte[memberBytesLength]
            : new byte[memberBytesLength];
        Encoding.UTF8.GetBytes(membershipId, memberBytes);

        int totalLength = versionBytes.Length + contextBytes.Length + memberBytes.Length;
        Span<byte> combinedContext = totalLength <= SharedConstants.LargeStackAllocationThreshold
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

            return HashWithGenericHashFromSpan(masterKey, combinedContext, KeySize);
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
        return hashResult.IsErr
            ? throw new InvalidOperationException(string.Format(Blake2BHashFailedMessage,
                hashResult.UnwrapErr().Message))
            : hashResult.Unwrap();
    }
}
