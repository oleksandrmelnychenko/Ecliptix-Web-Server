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
        byte[]? tempPrivKeyCopy = null;

        try
        {
            Result<SodiumSecureMemoryHandle, EcliptixProtocolFailure> allocResult =
                SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize)
                    .MapSodiumFailure();

            if (allocResult.IsErr)
            {
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(allocResult.UnwrapErr());
            }

            securePrivateKey = allocResult.Unwrap();

            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);

            Result<Unit, EcliptixProtocolFailure> writeResult =
                securePrivateKey.Write(tempPrivateKeyBytes).MapSodiumFailure();
            if (writeResult.IsErr)
            {
                securePrivateKey.Dispose();
                SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(writeResult.UnwrapErr());
            }

            SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
            tempPrivateKeyBytes = null;

            tempPrivKeyCopy = new byte[Constants.X25519PrivateKeySize];
            Result<Unit, EcliptixProtocolFailure> readResult = securePrivateKey.Read(tempPrivKeyCopy)
                .MapSodiumFailure();
            if (readResult.IsErr)
            {
                securePrivateKey.Dispose();
                SodiumInterop.SecureWipe(tempPrivKeyCopy).IgnoreResult();
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(readResult.UnwrapErr());
            }

            Result<byte[], EcliptixProtocolFailure> deriveResult = Result<byte[], EcliptixProtocolFailure>.Try(
                func: () => ScalarMult.Base(tempPrivKeyCopy),
                errorMapper: ex =>
                    EcliptixProtocolFailure.DeriveKey(
                        $"Failed to derive public key for OPK ID {preKeyId} using ScalarMult.Base.",
                        ex)
            );

            SodiumInterop.SecureWipe(tempPrivKeyCopy).IgnoreResult();
            tempPrivKeyCopy = null;

            if (deriveResult.IsErr)
            {
                securePrivateKey.Dispose();
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(deriveResult.UnwrapErr());
            }

            byte[] publicKeyBytes = deriveResult.Unwrap();

            if (publicKeyBytes.Length != Constants.X25519PublicKeySize)
            {
                securePrivateKey.Dispose();
                SodiumInterop.SecureWipe(publicKeyBytes).IgnoreResult();
                return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(EcliptixProtocolFailure.DeriveKey(
                    $"Derived public key for OPK ID {preKeyId} has incorrect size ({publicKeyBytes.Length})."));
            }

            OneTimePreKeyLocal opk = new(preKeyId, securePrivateKey, publicKeyBytes);
            return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Ok(opk);
        }
        catch (Exception ex)
        {
            securePrivateKey?.Dispose();
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes).IgnoreResult();
            if (tempPrivKeyCopy != null) SodiumInterop.SecureWipe(tempPrivKeyCopy).IgnoreResult();

            return Result<OneTimePreKeyLocal, EcliptixProtocolFailure>.Err(
                EcliptixProtocolFailure.Generic($"Unexpected failure during OPK Generation for ID {preKeyId}.", ex)
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