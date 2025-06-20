using Ecliptix.Domain.Utilities;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Ecliptix.Core.OpaqueProtocol;

public static class OpaqueCryptoUtilities
{
    private static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName("secp256r1");

    private static readonly ThreadLocal<Sha256Digest> DigestPool = new(() => new Sha256Digest());

    public static readonly ECDomainParameters DomainParams =
        new(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H);

    private const int AesGcmNonceLengthBytes = 12;
    private const int AesGcmTagLengthBits = 128;

    private static readonly SecureRandom SecureRandomInstance = new();

    public static Result<byte[], OpaqueFailure> HkdfExtract(byte[] ikm, byte[]? salt)
    {
        if (ikm.Length == 0)
            return Result<byte[], OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Input keying material (ikm) cannot be null or empty."));

        HMac hmac = new(new Sha256Digest());
        byte[] effectiveSalt = salt ?? new byte[hmac.GetMacSize()];

        try
        {
            hmac.Init(new KeyParameter(effectiveSalt));
            hmac.BlockUpdate(ikm, 0, ikm.Length);
            byte[] prk = new byte[hmac.GetMacSize()];
            hmac.DoFinal(prk, 0);
            return Result<byte[], OpaqueFailure>.Ok(prk);
        }
        catch (InvalidKeyException exc)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidKeySignature(exc.Message, exc));
        }
    }

    public static byte[] HkdfExpand(byte[] prk, byte[]? info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(HkdfParameters.SkipExtractParameters(prk, info));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static byte[] DeriveKey(byte[] ikm, byte[]? salt, byte[]? info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm, salt, info));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static Result<ECPoint, OpaqueFailure> HashToPoint(byte[] inputBytes)
    {
        Sha256Digest digest = DigestPool.Value!;
        byte counter = 0;
        const int maxAttempts = 255;

        while (counter < maxAttempts)
        {
            digest.Reset();
            digest.BlockUpdate(inputBytes, 0, inputBytes.Length);
            digest.BlockUpdate([counter], 0, 1);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            BigInteger scalar = new(1, hash);
            if (scalar.SignValue > 0 && scalar.CompareTo(DomainParams.N) < 0)
            {
                ECPoint point = DomainParams.G.Multiply(scalar).Normalize();
                if (point.IsValid())
                    return Result<ECPoint, OpaqueFailure>.Ok(point);
            }

            counter++;
        }

        return Result<ECPoint, OpaqueFailure>.Err(
            OpaqueFailure.HashingValidPointFailed("Failed to hash input to a valid curve point after 255 attempts."));
    }

    public static BigInteger GenerateRandomScalar()
    {
        BigInteger scalar;
        do
        {
            scalar = new BigInteger(DomainParams.N.BitLength, SecureRandomInstance);
        } while (scalar.SignValue <= 0 || scalar.CompareTo(DomainParams.N) >= 0);

        return scalar;
    }

    public static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        ECKeyPairGenerator generator = new();
        generator.Init(new ECKeyGenerationParameters(DomainParams, SecureRandomInstance));
        return generator.GenerateKeyPair();
    }

    public static Result<byte[], OpaqueFailure> Encrypt(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        byte[] nonce = new byte[AesGcmNonceLengthBytes];
        SecureRandomInstance.NextBytes(nonce);

        try
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            cipher.Init(true, new AeadParameters(new KeyParameter(key), AesGcmTagLengthBits, nonce, associatedData));
            byte[] ciphertext = cipher.DoFinal(plaintext);

            byte[] result = new byte[nonce.Length + ciphertext.Length];
            nonce.CopyTo(result, 0);
            ciphertext.CopyTo(result, nonce.Length);
            return Result<byte[], OpaqueFailure>.Ok(result);
        }
        catch (Exception ex) when (ex is InvalidKeyException or InvalidCipherTextException)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.AeadEncryptFailed(ex.Message, ex));
        }
    }

    public static Result<byte[], OpaqueFailure> Decrypt(byte[] ciphertextWithNonce, byte[] key,
        byte[] associatedData)
    {
        if (ciphertextWithNonce.Length < AesGcmNonceLengthBytes)
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.AeadDecryptFailed(""));

        ReadOnlySpan<byte> nonce = ciphertextWithNonce.AsSpan(0, AesGcmNonceLengthBytes);
        ReadOnlySpan<byte> ciphertext = ciphertextWithNonce.AsSpan(AesGcmNonceLengthBytes);

        IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        try
        {
            cipher.Init(false,
                new AeadParameters(new KeyParameter(key), AesGcmTagLengthBits, nonce.ToArray(), associatedData));
            byte[] plaintext = cipher.DoFinal(ciphertext.ToArray());
            return Result<byte[], OpaqueFailure>.Ok(plaintext);
        }
        catch (InvalidCipherTextException exc)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.AeadDecryptFailed(exc.Message, exc));
        }
    }
}