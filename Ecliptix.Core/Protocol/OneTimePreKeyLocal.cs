using Ecliptix.Core.Protocol.Failures;
using Ecliptix.Domain.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public readonly struct OneTimePreKeyLocal : IDisposable
{
    public uint PreKeyId { get; }
    public SodiumSecureMemoryHandle PrivateKeyHandle { get; }
    public byte[] PublicKey { get; }

    private OneTimePreKeyLocal(uint preKeyId, SodiumSecureMemoryHandle privateKeyHandle, byte[] publicKey)
    {
        PreKeyId = preKeyId;
        PrivateKeyHandle = privateKeyHandle;
        PublicKey = publicKey;
    }

    public static Result<OneTimePreKeyLocal, EcliptixProtocolFailure> Generate(uint preKeyId)
    {
        SodiumSecureMemoryHandle? securePrivateKey = null;
        byte[]? tempPrivateKeyBytes = null;

        try
        {
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);

            byte[] publicKeyBytes = ScalarMult.Base(tempPrivateKeyBytes);
            if (publicKeyBytes.Length != Constants.X25519PublicKeySize)
            {
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.DeriveKey(
                    $"Derived public key for OPK ID {preKeyId} has incorrect size ({publicKeyBytes.Length})."));
            }

            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize).MapSodiumFailure();
            if (allocResult.IsErr)
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(allocResult.UnwrapErr());
            securePrivateKey = allocResult.Unwrap();

            Result<Unit, EcliptixProtocolFailure> writeResult =
                securePrivateKey.Write(tempPrivateKeyBytes).MapSodiumFailure();
            if (writeResult.IsErr)
            {
                securePrivateKey.Dispose();
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
            }

            OneTimePreKeyLocal opk = new(preKeyId, securePrivateKey, publicKeyBytes);
            securePrivateKey = null;

            return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Ok(opk);
        }
        catch (Exception ex)
        {
            securePrivateKey?.Dispose();
            return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected failure during OPK Generation for ID {preKeyId}.", ex)
            );
        }
        finally
        {
            if (tempPrivateKeyBytes != null)
            {
                SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
            }
        }
    }

    public static Result<OneTimePreKeyLocal, EcliptixProtocolFailure> CreateFromSecretKey(uint preKeyId,
        byte[] privateKey)
    {
        SodiumSecureMemoryHandle? securePrivateKey = null;
        try
        {
            if (privateKey.Length != Constants.X25519PrivateKeySize)
            {
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.InvalidInput(
                    $"OPK private key for ID {preKeyId} has incorrect size ({privateKey.Length})."));
            }

            byte[] publicKey = ScalarMult.Base(privateKey);

            securePrivateKey = SodiumSecureMemoryHandle.Allocate(privateKey.Length).Unwrap();
            securePrivateKey.Write(privateKey).Unwrap();

            OneTimePreKeyLocal opk = new(preKeyId, securePrivateKey, publicKey);
            securePrivateKey = null;

            return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Ok(opk);
        }
        catch (Exception ex)
        {
            securePrivateKey?.Dispose();
            return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Failed to rehydrate OPK for ID {preKeyId}.", ex)
            );
        }
    }

    public static OneTimePreKeyLocal CreateFromParts(uint preKeyId, SodiumSecureMemoryHandle privateKeyHandle,
        byte[] publicKey)
    {
        return new OneTimePreKeyLocal(preKeyId, privateKeyHandle, publicKey);
    }

    public void Dispose()
    {
        PrivateKeyHandle?.Dispose();
    }
}