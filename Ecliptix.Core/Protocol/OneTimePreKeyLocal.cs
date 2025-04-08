using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public readonly struct OneTimePreKeyLocal : IDisposable
{
    public readonly uint PreKeyId;
    public readonly SodiumSecureMemoryHandle PrivateKeyHandle;
    public readonly byte[] PublicKey;

    private OneTimePreKeyLocal(uint preKeyId, SodiumSecureMemoryHandle privateKeyHandle, byte[] publicKey)
    {
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
            securePrivateKey = SodiumSecureMemoryHandle.Allocate(Constants.X25519PrivateKeySize);
            tempPrivateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519PrivateKeySize);

            securePrivateKey.Write(tempPrivateKeyBytes);

            SodiumInterop.SecureWipe(tempPrivateKeyBytes); 
            tempPrivateKeyBytes = null; 

            byte[] tempPrivKeyCopy = new byte[Constants.X25519PrivateKeySize];
            securePrivateKey.Read(tempPrivKeyCopy); 
            byte[] publicKeyBytes = ScalarMult.Base(tempPrivKeyCopy);
            SodiumInterop.SecureWipe(tempPrivKeyCopy); 

            return Result<OneTimePreKeyLocal, ShieldError>.Ok(
                new OneTimePreKeyLocal(preKeyId, securePrivateKey, publicKeyBytes)
            );
        }
        catch (Exception ex)
        {
            securePrivateKey?.Dispose();
            if (tempPrivateKeyBytes != null) SodiumInterop.SecureWipe(tempPrivateKeyBytes);

            return Result<OneTimePreKeyLocal, ShieldError>.Err(
                ShieldError.DeriveKey($"Failed OPK Gen ID {preKeyId}.", ex)
            );
        }
    }

    public void Dispose()
    {
        PrivateKeyHandle?.Dispose();
    }
}