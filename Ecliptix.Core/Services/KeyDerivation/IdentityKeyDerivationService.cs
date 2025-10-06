using System.Reflection;
using System.Security.Cryptography;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;
using Ecliptix.Utilities.Failures.Sodium;
using Serilog;

namespace Ecliptix.Core.Services.KeyDerivation;

public interface IIdentityKeyDerivationService
{
    Task<Result<EcliptixSystemIdentityKeys, KeySplittingFailure>> DeriveIdentityKeysFromMasterKeyAsync(
        SodiumSecureMemoryHandle masterKeyHandle,
        Guid membershipId);
}

public class IdentityKeyDerivationService : IIdentityKeyDerivationService
{
    private const uint DefaultOneTimeKeyCount = 100;
    private const int MasterKeyReadSize = 32;
    private const int RandomIdMinValue = 1;

    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key";
    private const string ErrorMessageEd25519GenerationFailed = "Failed to generate Ed25519 keys";
    private const string ErrorMessageX25519GenerationFailed = "Failed to generate X25519 keys";
    private const string ErrorMessageSignedPreKeyFailed = "Failed to generate signed pre-key";
    private const string ErrorMessageOneTimePreKeysFailed = "Failed to generate one-time pre-keys";
    private const string ErrorMessageIdentityKeysCreationFailed = "Failed to create identity keys";
    private const string ErrorMessageUnexpectedError = "Unexpected error during identity key derivation";
    private const string ErrorMessageEd25519KeyGenFromSeedFailed = "Ed25519 key generation from seed failed";
    private const string ErrorMessageSecureMemoryAllocationFailed = "Failed to allocate secure memory";
    private const string ErrorMessageSecureMemoryWriteFailed = "Failed to write to secure memory";
    private const string ErrorMessageUnexpectedEd25519Error = "Unexpected error generating Ed25519 key pair from seed";
    private const string ErrorMessageX25519PublicKeyDeriveFailed = "Failed to derive X25519 public key";
    private const string ErrorMessageX25519SecureMemoryAllocationFailed = "Failed to allocate secure memory for X25519";
    private const string ErrorMessageX25519SecureMemoryWriteFailed = "Failed to write X25519 secret key to secure memory";
    private const string ErrorMessageUnexpectedX25519Error = "Unexpected error generating X25519 key pair from seed";
    private const string ErrorMessageSpkPublicKeyDeriveFailed = "Failed to derive SPK public key";
    private const string ErrorMessageSpkSecureMemoryAllocationFailed = "Failed to allocate secure memory for SPK";
    private const string ErrorMessageSpkSecureMemoryWriteFailed = "Failed to write SPK to secure memory";
    private const string ErrorMessageEd25519SecretKeyReadFailed = "Failed to read Ed25519 secret key";
    private const string ErrorMessageSignPreKeyFailed = "Failed to sign pre-key";
    private const string ErrorMessageUnexpectedSpkError = "Unexpected error generating signed pre-key";
    private const string ErrorMessageUnexpectedOpkError = "Unexpected error generating one-time pre-keys";
    private const string ErrorMessageConstructorNotFound = "Failed to find EcliptixSystemIdentityKeys constructor";
    private const string ErrorMessageIdentityKeysCreationException = "Failed to create identity keys";

    private const string OneTimePreKeyIdFormat = "OneTimePreKey_{0}";

    public async Task<Result<EcliptixSystemIdentityKeys, KeySplittingFailure>> DeriveIdentityKeysFromMasterKeyAsync(
        SodiumSecureMemoryHandle masterKeyHandle,
        Guid membershipId)
    {
        byte[]? masterKeyBytes = null;
        byte[]? ed25519Seed = null;
        byte[]? x25519Seed = null;
        SodiumSecureMemoryHandle? ed25519SkHandle = null;
        SodiumSecureMemoryHandle? x25519SkHandle = null;

        try
        {
            Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(MasterKeyReadSize);
            if (readResult.IsErr)
            {
                SodiumFailure error = readResult.UnwrapErr();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyReadFailed}: {error.Message}"));
            }

            masterKeyBytes = readResult.Unwrap();
            string membershipIdString = membershipId.ToString();

            ed25519Seed = await Task.Run(() => MasterKeyDerivation.DeriveEd25519Seed(masterKeyBytes, membershipIdString));
            x25519Seed = await Task.Run(() => MasterKeyDerivation.DeriveX25519Seed(masterKeyBytes, membershipIdString));

            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> ed25519Result =
                GenerateEd25519KeyPairFromSeed(ed25519Seed);
            if (ed25519Result.IsErr)
            {
                EcliptixProtocolFailure error = ed25519Result.UnwrapErr();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageEd25519GenerationFailed}: {error.Message}"));
            }

            (ed25519SkHandle, byte[] ed25519Pk) = ed25519Result.Unwrap();

            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> x25519Result =
                GenerateX25519KeyPairFromSeed(x25519Seed);
            if (x25519Result.IsErr)
            {
                EcliptixProtocolFailure error = x25519Result.UnwrapErr();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageX25519GenerationFailed}: {error.Message}"));
            }

            (x25519SkHandle, byte[] x25519Pk) = x25519Result.Unwrap();

            Result<(uint id, SodiumSecureMemoryHandle sk, byte[] pk, byte[] sig), EcliptixProtocolFailure> spkResult =
                GenerateSignedPreKey(ed25519SkHandle, ed25519Pk, masterKeyBytes, membershipIdString);
            if (spkResult.IsErr)
            {
                EcliptixProtocolFailure error = spkResult.UnwrapErr();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageSignedPreKeyFailed}: {error.Message}"));
            }

            (uint spkId, SodiumSecureMemoryHandle spkSk, byte[] spkPk, byte[] spkSig) = spkResult.Unwrap();

            Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure> opksResult =
                GenerateOneTimePreKeys(DefaultOneTimeKeyCount);
            if (opksResult.IsErr)
            {
                EcliptixProtocolFailure error = opksResult.UnwrapErr();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageOneTimePreKeysFailed}: {error.Message}"));
            }

            List<OneTimePreKeyLocal> opks = opksResult.Unwrap();

            Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> keysResult =
                CreateIdentityKeys(ed25519SkHandle, ed25519Pk, x25519SkHandle, x25519Pk,
                    spkId, spkSk, spkPk, spkSig, opks);

            if (keysResult.IsErr)
            {
                EcliptixProtocolFailure error = keysResult.UnwrapErr();
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageIdentityKeysCreationFailed}: {error.Message}"));
            }

            ed25519SkHandle = null;
            x25519SkHandle = null;

            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Ok(keysResult.Unwrap());
        }
        catch (Exception ex)
        {
            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedError, ex));
        }
        finally
        {
            if (masterKeyBytes != null)
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            if (ed25519Seed != null)
                CryptographicOperations.ZeroMemory(ed25519Seed);
            if (x25519Seed != null)
                CryptographicOperations.ZeroMemory(x25519Seed);

            ed25519SkHandle?.Dispose();
            x25519SkHandle?.Dispose();
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> GenerateEd25519KeyPairFromSeed(byte[] seed)
    {
        SodiumSecureMemoryHandle? skHandle = null;
        byte[]? skBytes = null;

        try
        {
            Result<(byte[] PublicKey, byte[] SecretKey), SodiumFailure> keyPairResult =
                SodiumInterop.GenerateSigningKeyPairFromSeed(seed);

            if (keyPairResult.IsErr)
            {
                SodiumFailure error = keyPairResult.UnwrapErr();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageEd25519KeyGenFromSeedFailed}: {error.Message}"));
            }

            (byte[] pk, byte[] sk) = keyPairResult.Unwrap();
            skBytes = sk;

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.Ed25519SecretKeySize);

            if (allocResult.IsErr)
            {
                SodiumFailure error = allocResult.UnwrapErr();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageSecureMemoryAllocationFailed}: {error.Message}"));
            }

            skHandle = allocResult.Unwrap();
            Result<Unit, SodiumFailure> writeResult = skHandle.Write(skBytes);

            if (writeResult.IsErr)
            {
                skHandle?.Dispose();
                SodiumFailure error = writeResult.UnwrapErr();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageSecureMemoryWriteFailed}: {error.Message}"));
            }

            SodiumSecureMemoryHandle result = skHandle;
            skHandle = null;

            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((result, pk));
        }
        catch (Exception ex)
        {
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"{ErrorMessageUnexpectedEd25519Error}: {ex.Message}", ex));
        }
        finally
        {
            if (skBytes != null)
                CryptographicOperations.ZeroMemory(skBytes);
            skHandle?.Dispose();
        }
    }

    private static Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> GenerateX25519KeyPairFromSeed(byte[] seed)
    {
        SodiumSecureMemoryHandle? skHandle = null;

        try
        {
            Result<byte[], SodiumFailure> publicKeyResult = SodiumInterop.ScalarMultBase(seed);

            if (publicKeyResult.IsErr)
            {
                SodiumFailure error = publicKeyResult.UnwrapErr();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageX25519PublicKeyDeriveFailed}: {error.Message}"));
            }

            byte[] publicKey = publicKeyResult.Unwrap();

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);

            if (allocResult.IsErr)
            {
                SodiumFailure error = allocResult.UnwrapErr();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageX25519SecureMemoryAllocationFailed}: {error.Message}"));
            }

            skHandle = allocResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = skHandle.Write(seed);

            if (writeResult.IsErr)
            {
                skHandle.Dispose();
                SodiumFailure error = writeResult.UnwrapErr();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageX25519SecureMemoryWriteFailed}: {error.Message}"));
            }

            SodiumSecureMemoryHandle result = skHandle;
            skHandle = null;

            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((result, publicKey));
        }
        catch (Exception ex)
        {
            skHandle?.Dispose();
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"{ErrorMessageUnexpectedX25519Error}: {ex.Message}", ex));
        }
    }

    private static Result<(uint id, SodiumSecureMemoryHandle sk, byte[] pk, byte[] sig), EcliptixProtocolFailure> GenerateSignedPreKey(
        SodiumSecureMemoryHandle ed25519SkHandle,
        byte[] identityPublicKey,
        byte[] masterKey,
        string membershipId)
    {
        byte[]? spkSeed = null;
        byte[]? spkPrivateKey = null;
        SodiumSecureMemoryHandle? spkSk = null;

        try
        {
            spkSeed = MasterKeyDerivation.DeriveSignedPreKeySeed(masterKey, membershipId);
            uint spkId = BitConverter.ToUInt32(spkSeed, 0);

            spkPrivateKey = new byte[Constants.X25519PrivateKeySize];
            Array.Copy(spkSeed, 0, spkPrivateKey, 0, Constants.X25519PrivateKeySize);

            Result<byte[], SodiumFailure> publicKeyResult = SodiumInterop.ScalarMultBase(spkPrivateKey);
            if (publicKeyResult.IsErr)
            {
                SodiumFailure error = publicKeyResult.UnwrapErr();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageSpkPublicKeyDeriveFailed}: {error.Message}"));
            }

            byte[] spkPk = publicKeyResult.Unwrap();

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            if (allocResult.IsErr)
            {
                SodiumFailure error = allocResult.UnwrapErr();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageSpkSecureMemoryAllocationFailed}: {error.Message}"));
            }

            spkSk = allocResult.Unwrap();
            Result<Unit, SodiumFailure> writeResult = spkSk.Write(spkPrivateKey);
            if (writeResult.IsErr)
            {
                spkSk.Dispose();
                SodiumFailure error = writeResult.UnwrapErr();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageSpkSecureMemoryWriteFailed}: {error.Message}"));
            }

            Result<byte[], SodiumFailure> readSkResult = ed25519SkHandle.ReadBytes(Constants.Ed25519SecretKeySize);
            if (readSkResult.IsErr)
            {
                spkSk.Dispose();
                SodiumFailure error = readSkResult.UnwrapErr();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageEd25519SecretKeyReadFailed}: {error.Message}"));
            }

            byte[] ed25519Sk = readSkResult.Unwrap();

            Result<byte[], SodiumFailure> signResult =
                SodiumInterop.SignDetached(spkPk, ed25519Sk);

            CryptographicOperations.ZeroMemory(ed25519Sk);

            if (signResult.IsErr)
            {
                spkSk.Dispose();
                SodiumFailure error = signResult.UnwrapErr();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"{ErrorMessageSignPreKeyFailed}: {error.Message}"));
            }

            byte[] signature = signResult.Unwrap();

            SodiumSecureMemoryHandle resultHandle = spkSk;
            spkSk = null;

            return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Ok(
                (spkId, resultHandle, spkPk, signature));
        }
        catch (Exception ex)
        {
            spkSk?.Dispose();
            return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"{ErrorMessageUnexpectedSpkError}: {ex.Message}", ex));
        }
        finally
        {
            if (spkSeed != null)
                CryptographicOperations.ZeroMemory(spkSeed);
            if (spkPrivateKey != null)
                CryptographicOperations.ZeroMemory(spkPrivateKey);
        }
    }

    private static Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure> GenerateOneTimePreKeys(uint count)
    {
        List<OneTimePreKeyLocal> opks = [];

        try
        {
            for (uint i = 0; i < count; i++)
            {
                uint opkId = (uint)Random.Shared.Next(RandomIdMinValue, int.MaxValue);

                Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> keyPairResult =
                    SodiumInterop.GenerateX25519KeyPair(string.Format(OneTimePreKeyIdFormat, opkId));

                if (keyPairResult.IsErr)
                {
                    foreach (OneTimePreKeyLocal opk in opks)
                    {
                        opk.PrivateKeyHandle.Dispose();
                    }

                    EcliptixProtocolFailure error = keyPairResult.UnwrapErr();
                    return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Err(error);
                }

                (SodiumSecureMemoryHandle sk, byte[] pk) = keyPairResult.Unwrap();
                opks.Add(OneTimePreKeyLocal.CreateFromParts(opkId, sk, pk));
            }

            return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Ok(opks);
        }
        catch (Exception ex)
        {
            foreach (OneTimePreKeyLocal opk in opks)
            {
                opk.PrivateKeyHandle.Dispose();
            }

            return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"{ErrorMessageUnexpectedOpkError}: {ex.Message}", ex));
        }
    }

    private static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> CreateIdentityKeys(
        SodiumSecureMemoryHandle edSk, byte[] edPk,
        SodiumSecureMemoryHandle idSk, byte[] idPk,
        uint spkId, SodiumSecureMemoryHandle spkSk, byte[] spkPk, byte[] spkSig,
        List<OneTimePreKeyLocal> opks)
    {
        try
        {
            ConstructorInfo? constructor = typeof(EcliptixSystemIdentityKeys).GetConstructor(
                BindingFlags.NonPublic | BindingFlags.Instance,
                null,
                [
                    typeof(SodiumSecureMemoryHandle), typeof(byte[]),
                    typeof(SodiumSecureMemoryHandle), typeof(byte[]),
                    typeof(uint), typeof(SodiumSecureMemoryHandle), typeof(byte[]), typeof(byte[]),
                    typeof(List<OneTimePreKeyLocal>)
                ],
                null);

            if (constructor == null)
            {
                return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic(ErrorMessageConstructorNotFound));
            }

            EcliptixSystemIdentityKeys keys = (EcliptixSystemIdentityKeys)constructor.Invoke(new object[]
            {
                edSk, edPk, idSk, idPk, spkId, spkSk, spkPk, spkSig, opks
            });

            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Ok(keys);
        }
        catch (Exception ex)
        {
            return Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"{ErrorMessageIdentityKeysCreationException}: {ex.Message}", ex));
        }
    }
}
