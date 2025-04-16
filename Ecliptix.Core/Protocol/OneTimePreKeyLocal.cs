using Ecliptix.Core.Protocol.Utilities;
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

    public static Result<OneTimePreKeyLocal, ShieldFailure> Generate(uint preKeyId)
    {
        SodiumSecureMemoryHandle? securePrivateKey = null;
        byte[]? tempPrivateKeyBytes = null;
        byte[]? tempPrivKeyCopy = null;

        try
        {
            Result<SodiumSecureMemoryHandle, ShieldFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            if (allocResult.IsErr)
                return Result<OneTimePreKeyLocal, ShieldFailure>.Err(allocResult.UnwrapErr());
            securePrivateKey = allocResult.Unwrap();

            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);

            Result<Unit, ShieldFailure> writeResult = securePrivateKey.Write(tempPrivateKeyBytes);
            if (writeResult.IsErr)
            {
                securePrivateKey.Dispose();
                SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
                return Result<OneTimePreKeyLocal, ShieldFailure>.Err(writeResult.UnwrapErr());
            }

            SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
            tempPrivateKeyBytes = null;

            tempPrivKeyCopy = new byte[Constants.X25519PrivateKeySize];
            Result<Unit, ShieldFailure> readResult = securePrivateKey.Read(tempPrivKeyCopy);
            if (readResult.IsErr)
            {
                securePrivateKey.Dispose();
                SodiumInterop.SecureWipe(tempPrivKeyCopy).IgnoreResult();
                return Result<OneTimePreKeyLocal, ShieldFailure>.Err(readResult.UnwrapErr());
            }

            Result<byte[], ShieldFailure> deriveResult = Result<byte[], ShieldFailure>.Try(
                func: () => ScalarMult.Base(tempPrivKeyCopy),
                errorMapper: ex =>
                    ShieldFailure.DeriveKey($"Failed to derive public key for OPK ID {preKeyId} using ScalarMult.Base.",
                        ex)
            );

            SodiumInterop.SecureWipe(tempPrivKeyCopy).IgnoreResult();
            tempPrivKeyCopy = null;

            if (deriveResult.IsErr)
            {
                securePrivateKey.Dispose();
                return Result<OneTimePreKeyLocal, ShieldFailure>.Err(deriveResult.UnwrapErr());
            }

            byte[] publicKeyBytes = deriveResult.Unwrap();

            if (publicKeyBytes.Length != Constants.X25519PublicKeySize)
            {
                securePrivateKey.Dispose();
                SodiumInterop.SecureWipe(publicKeyBytes).IgnoreResult();
                return Result<OneTimePreKeyLocal, ShieldFailure>.Err(ShieldFailure.DeriveKey(
                    $"Derived public key for OPK ID {preKeyId} has incorrect size ({publicKeyBytes.Length})."));
            }

            OneTimePreKeyLocal opk = new(preKeyId, securePrivateKey, publicKeyBytes);
            return Result<OneTimePreKeyLocal, ShieldFailure>.Ok(opk);
        }
        catch (Exception ex)
        {
            securePrivateKey?.Dispose();
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
            if (tempPrivKeyCopy != null) SodiumInterop.SecureWipe(tempPrivKeyCopy).IgnoreResult();

            return Result<OneTimePreKeyLocal, ShieldFailure>.Err(
                ShieldFailure.Generic($"Unexpected failure during OPK Generation for ID {preKeyId}.", ex)
            );
        }
    }

    public void Dispose()
    {
        if (PrivateKeyHandle is { IsInvalid: false })
        {
            PrivateKeyHandle.Dispose();
        }
    }
}