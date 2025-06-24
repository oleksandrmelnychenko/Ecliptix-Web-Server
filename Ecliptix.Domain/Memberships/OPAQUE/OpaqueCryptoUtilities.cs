using Ecliptix.Domain.Utilities;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public static class OpaqueCryptoUtilities
{
    private static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName("secp256r1");

    public static readonly ECDomainParameters DomainParams =
        new(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H);

    private static readonly ThreadLocal<Sha256Digest> DigestPool = new(() => new Sha256Digest());
    private static readonly SecureRandom SecureRandomInstance = new();

    public static AsymmetricCipherKeyPair GenerateKeyPairFromSeed(byte[] seed)
    {
        BigInteger? d = new(1, seed);
        d = d.Mod(DomainParams.N.Subtract(BigInteger.One)).Add(BigInteger.One);

        ECPoint q = DomainParams.G.Multiply(d).Normalize();
        ECPrivateKeyParameters privateKey = new(d, DomainParams);
        ECPublicKeyParameters publicKey = new(q, DomainParams);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    public static Result<byte[], OpaqueFailure> HkdfExtract(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt)
    {
        if (ikm.IsEmpty) return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput());

        HMac hmac = new(new Sha256Digest());
        ReadOnlySpan<byte> effectiveSalt = salt.IsEmpty ? stackalloc byte[hmac.GetMacSize()] : salt;

        try
        {
            hmac.Init(new KeyParameter(effectiveSalt.ToArray()));
            hmac.BlockUpdate(ikm.ToArray(), 0, ikm.Length);
            byte[] prk = new byte[hmac.GetMacSize()];
            hmac.DoFinal(prk, 0);
            return Result<byte[], OpaqueFailure>.Ok(prk);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidKeySignature(ex.Message, ex));
        }
    }

    public static byte[] HkdfExpand(byte[] prk, ReadOnlySpan<byte> info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(HkdfParameters.SkipExtractParameters(prk, info.ToArray()));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static byte[] DeriveKey(byte[] ikm, byte[]? salt, ReadOnlySpan<byte> info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm, salt, info.ToArray()));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        ECKeyPairGenerator generator = new();
        generator.Init(new ECKeyGenerationParameters(DomainParams, SecureRandomInstance));
        return generator.GenerateKeyPair();
    }

    public static Result<byte[], OpaqueFailure> Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData)
    {
        try
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            byte[] nonce = new byte[OpaqueConstants.AesGcmNonceLengthBytes];
            SecureRandomInstance.NextBytes(nonce);

            AeadParameters cipherParams = new(new KeyParameter(key), OpaqueConstants.AesGcmTagLengthBits, nonce,
                associatedData);
            cipher.Init(true, cipherParams);

            int outputSize = cipher.GetOutputSize(plaintext.Length);
            byte[] result = new byte[OpaqueConstants.AesGcmNonceLengthBytes + outputSize];

            nonce.CopyTo(result, 0);

            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, result,
                OpaqueConstants.AesGcmNonceLengthBytes);
            cipher.DoFinal(result, OpaqueConstants.AesGcmNonceLengthBytes + len);

            return Result<byte[], OpaqueFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.EncryptFailed(ex.Message, ex));
        }
    }

    public static Result<byte[], OpaqueFailure> Decrypt(byte[] ciphertextWithNonce, byte[] key, byte[]? associatedData)
    {
        if (ciphertextWithNonce.Length < OpaqueConstants.AesGcmNonceLengthBytes)
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.DecryptFailed());

        ReadOnlySpan<byte> fullSpan = ciphertextWithNonce.AsSpan();
        ReadOnlySpan<byte> nonce = fullSpan[..OpaqueConstants.AesGcmNonceLengthBytes];
        ReadOnlySpan<byte> ciphertext = fullSpan[OpaqueConstants.AesGcmNonceLengthBytes..];

        try
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            AeadParameters cipherParams = new(new KeyParameter(key), OpaqueConstants.AesGcmTagLengthBits,
                nonce.ToArray(), associatedData);
            cipher.Init(false, cipherParams);

            return Result<byte[], OpaqueFailure>.Ok(cipher.DoFinal(ciphertext.ToArray()));
        }
        catch (InvalidCipherTextException ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.DecryptFailed(ex.Message, ex));
        }
    }
}