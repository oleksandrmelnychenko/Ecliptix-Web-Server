using Ecliptix.Core.Protocol.Utilities;
using Sodium;

namespace Ecliptix.Core.Protocol;

public readonly struct OneTimePreKeyLocal
{
    public readonly uint PreKeyId;
    public readonly byte[] PrivateKey;
    public readonly byte[] PublicKey;

    private OneTimePreKeyLocal(uint preKeyId, byte[] privateKey, byte[] publicKey)
    {
        if (privateKey is not { Length: Constants.X25519KeySize })
            throw new ArgumentException("Invalid private key size", nameof(privateKey));
        if (publicKey is not { Length: Constants.X25519KeySize })
            throw new ArgumentException("Invalid public key size", nameof(publicKey));

        PreKeyId = preKeyId;
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }

    public static Result<OneTimePreKeyLocal, ShieldError> Generate(uint preKeyId)
    {
        byte[]? privateKeyBytes = null;
        
        try
        {
            privateKeyBytes = SodiumCore.GetRandomBytes(Constants.X25519KeySize);
            byte[] publicKey = ScalarMult.Base(privateKeyBytes);

            return Result<OneTimePreKeyLocal, ShieldError>.Ok(
                new OneTimePreKeyLocal(preKeyId, privateKeyBytes, publicKey)
            );
        }
        catch (Exception ex)
        {
            if (privateKeyBytes != null)
            {
                Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);
            }

            return Result<OneTimePreKeyLocal, ShieldError>.Err(
                ShieldError.DeriveKey($"Failed to generate X25519 key pair for PreKeyId {preKeyId}.", ex)
            );
        }
    }
}
