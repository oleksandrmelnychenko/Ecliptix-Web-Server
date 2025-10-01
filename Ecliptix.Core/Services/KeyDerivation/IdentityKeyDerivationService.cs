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
    private const uint DEFAULT_ONE_TIME_KEY_COUNT = 100;

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
            Result<byte[], SodiumFailure> readResult = masterKeyHandle.ReadBytes(32);
            if (readResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to read master key: {readResult.UnwrapErr().Message}"));
            }

            masterKeyBytes = readResult.Unwrap();
            string membershipIdString = membershipId.ToString();

            ed25519Seed = await Task.Run(() => MasterKeyDerivation.DeriveEd25519Seed(masterKeyBytes, membershipIdString));
            x25519Seed = await Task.Run(() => MasterKeyDerivation.DeriveX25519Seed(masterKeyBytes, membershipIdString));

            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> ed25519Result =
                GenerateEd25519KeyPairFromSeed(ed25519Seed);
            if (ed25519Result.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate Ed25519 keys: {ed25519Result.UnwrapErr().Message}"));
            }

            (ed25519SkHandle, byte[] ed25519Pk) = ed25519Result.Unwrap();

            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> x25519Result =
                GenerateX25519KeyPairFromSeed(x25519Seed);
            if (x25519Result.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate X25519 keys: {x25519Result.UnwrapErr().Message}"));
            }

            (x25519SkHandle, byte[] x25519Pk) = x25519Result.Unwrap();

            Result<(uint id, SodiumSecureMemoryHandle sk, byte[] pk, byte[] sig), EcliptixProtocolFailure> spkResult =
                GenerateSignedPreKey(ed25519SkHandle, ed25519Pk);
            if (spkResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate signed pre-key: {spkResult.UnwrapErr().Message}"));
            }

            (uint spkId, SodiumSecureMemoryHandle spkSk, byte[] spkPk, byte[] spkSig) = spkResult.Unwrap();

            Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure> opksResult =
                GenerateOneTimePreKeys(DEFAULT_ONE_TIME_KEY_COUNT);
            if (opksResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate one-time pre-keys: {opksResult.UnwrapErr().Message}"));
            }

            List<OneTimePreKeyLocal> opks = opksResult.Unwrap();

            Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> keysResult =
                CreateIdentityKeys(ed25519SkHandle, ed25519Pk, x25519SkHandle, x25519Pk,
                    spkId, spkSk, spkPk, spkSig, opks);

            if (keysResult.IsErr)
            {
                return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to create identity keys: {keysResult.UnwrapErr().Message}"));
            }

            Log.Information("Successfully derived identity keys from master key for membership {MembershipId}", membershipId);

            ed25519SkHandle = null;
            x25519SkHandle = null;

            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Ok(keysResult.Unwrap());
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error deriving identity keys from master key for membership {MembershipId}", membershipId);
            return Result<EcliptixSystemIdentityKeys, KeySplittingFailure>.Err(
                KeySplittingFailure.KeyDerivationFailed("Unexpected error during identity key derivation", ex));
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
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Ed25519 key generation from seed failed: {keyPairResult.UnwrapErr().Message}"));
            }

            (byte[] pk, byte[] sk) = keyPairResult.Unwrap();
            skBytes = sk;

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.Ed25519SecretKeySize);

            if (allocResult.IsErr)
            {
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to allocate secure memory: {allocResult.UnwrapErr().Message}"));
            }

            skHandle = allocResult.Unwrap();
            Result<Unit, SodiumFailure> writeResult = skHandle.Write(skBytes);

            if (writeResult.IsErr)
            {
                skHandle?.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to write to secure memory: {writeResult.UnwrapErr().Message}"));
            }

            SodiumSecureMemoryHandle result = skHandle;
            skHandle = null; 

            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((result, pk));
        }
        catch (Exception ex)
        {
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected error generating Ed25519 key pair from seed: {ex.Message}", ex));
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
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to derive X25519 public key: {publicKeyResult.UnwrapErr().Message}"));
            }

            byte[] publicKey = publicKeyResult.Unwrap();

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);

            if (allocResult.IsErr)
            {
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to allocate secure memory for X25519: {allocResult.UnwrapErr().Message}"));
            }

            skHandle = allocResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = skHandle.Write(seed);

            if (writeResult.IsErr)
            {
                skHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to write X25519 secret key to secure memory: {writeResult.UnwrapErr().Message}"));
            }

            SodiumSecureMemoryHandle result = skHandle;
            skHandle = null; 

            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Ok((result, publicKey));
        }
        catch (Exception ex)
        {
            skHandle?.Dispose();
            return Result<(SodiumSecureMemoryHandle, byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected error generating X25519 key pair from seed: {ex.Message}", ex));
        }
    }

    private static Result<(uint id, SodiumSecureMemoryHandle sk, byte[] pk, byte[] sig), EcliptixProtocolFailure> GenerateSignedPreKey(
        SodiumSecureMemoryHandle ed25519SkHandle,
        byte[] identityPublicKey)
    {
        try
        {
            uint spkId = (uint)Random.Shared.Next(1, int.MaxValue);

            Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> keyPairResult =
                SodiumInterop.GenerateX25519KeyPair("SignedPreKey");

            if (keyPairResult.IsErr)
            {
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(keyPairResult.UnwrapErr());
            }

            (SodiumSecureMemoryHandle spkSk, byte[] spkPk) = keyPairResult.Unwrap();

            byte[] signatureMessage = new byte[identityPublicKey.Length + sizeof(uint) + spkPk.Length];
            Buffer.BlockCopy(identityPublicKey, 0, signatureMessage, 0, identityPublicKey.Length);
            BitConverter.TryWriteBytes(signatureMessage.AsSpan(identityPublicKey.Length), spkId);
            Buffer.BlockCopy(spkPk, 0, signatureMessage, identityPublicKey.Length + sizeof(uint), spkPk.Length);

            Result<byte[], SodiumFailure> readSkResult = ed25519SkHandle.ReadBytes(Constants.Ed25519SecretKeySize);
            if (readSkResult.IsErr)
            {
                spkSk.Dispose();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to read Ed25519 secret key: {readSkResult.UnwrapErr().Message}"));
            }

            byte[] ed25519Sk = readSkResult.Unwrap();

            Result<byte[], SodiumFailure> signResult =
                SodiumInterop.SignDetached(signatureMessage, ed25519Sk);

            CryptographicOperations.ZeroMemory(ed25519Sk);

            if (signResult.IsErr)
            {
                spkSk.Dispose();
                return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                    EcliptixProtocolFailure.Generic($"Failed to sign pre-key: {signResult.UnwrapErr().Message}"));
            }

            byte[] signature = signResult.Unwrap();

            return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Ok(
                (spkId, spkSk, spkPk, signature));
        }
        catch (Exception ex)
        {
            return Result<(uint, SodiumSecureMemoryHandle, byte[], byte[]), EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected error generating signed pre-key: {ex.Message}", ex));
        }
    }

    private static Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure> GenerateOneTimePreKeys(uint count)
    {
        List<OneTimePreKeyLocal> opks = [];

        try
        {
            for (uint i = 0; i < count; i++)
            {
                uint opkId = (uint)Random.Shared.Next(1, int.MaxValue);

                Result<(SodiumSecureMemoryHandle skHandle, byte[] pk), EcliptixProtocolFailure> keyPairResult =
                    SodiumInterop.GenerateX25519KeyPair($"OneTimePreKey_{opkId}");

                if (keyPairResult.IsErr)
                {
                    foreach (OneTimePreKeyLocal opk in opks)
                    {
                        opk.PrivateKeyHandle.Dispose();
                    }

                    return Result<List<OneTimePreKeyLocal>, EcliptixProtocolFailure>.Err(keyPairResult.UnwrapErr());
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
                EcliptixProtocolFailure.Generic($"Unexpected error generating one-time pre-keys: {ex.Message}", ex));
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
                    EcliptixProtocolFailure.Generic("Failed to find EcliptixSystemIdentityKeys constructor"));
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
                EcliptixProtocolFailure.Generic($"Failed to create identity keys: {ex.Message}", ex));
        }
    }
}
