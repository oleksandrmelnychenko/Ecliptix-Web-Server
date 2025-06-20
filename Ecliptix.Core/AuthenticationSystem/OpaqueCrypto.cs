using System.Data;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Ecliptix.Core.AuthenticationSystem;

public static class OpaqueCrypto
{
    private static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName("secp256r1");

    public static readonly ECDomainParameters DomainParams =
        new(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H);

    public static byte[] HkdfExtract(byte[] ikm, byte[] salt)
    {
        HMac hmac = new(new Sha256Digest());
        if (salt.Length == 0)
        {
            salt = new byte[hmac.GetMacSize()];
        }

        hmac.Init(new KeyParameter(salt));
        hmac.BlockUpdate(ikm, 0, ikm.Length);
        byte[] prk = new byte[hmac.GetMacSize()];
        hmac.DoFinal(prk, 0);
        return prk;
    }

    public static byte[] HkdfExpand(byte[] prk, byte[] info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(HkdfParameters.SkipExtractParameters(prk, info));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static ECPoint HashToPoint(string input)
    {
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        Sha256Digest digest = new();
        byte[] counter = [0];

        while (true)
        {
            digest.BlockUpdate(inputBytes, 0, inputBytes.Length);
            digest.BlockUpdate(counter, 0, counter.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            try
            {
                BigInteger scalar = new(1, hash);
                return DomainParams.G.Multiply(scalar).Normalize();
            }
            catch (Exception)
            {
                // ignored
            }

            counter[0]++;
            if (counter[0] == 0)
            {
                throw new EvaluateException("Failed to hash input to a valid curve point after 256 attempts.");
            }
        }
    }

    public static byte[] DeriveKey(byte[] ikm, byte[]? salt, byte[] info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm, salt, info));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static BigInteger GenerateRandomScalar()
    {
        SecureRandom random = new();
        BigInteger scalar;

        do
        {
            scalar = new BigInteger(DomainParams.N.BitLength, random);
        } while (scalar.SignValue <= 0 || scalar.CompareTo(DomainParams.N) >= 0);

        return scalar;
    }

    public static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        ECKeyPairGenerator generator = new();
        generator.Init(new ECKeyGenerationParameters(DomainParams, new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    public static byte[] AeadEncrypt(byte[] plaintext, byte[] key, byte[] associatedData)
    {
        byte[] nonce = new byte[12];
        new SecureRandom().NextBytes(nonce);
        IBufferedCipher? cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));
        byte[]? ciphertext = cipher.DoFinal(plaintext);

        return nonce.Concat(ciphertext).ToArray();
    }

    public static byte[] AeadDecrypt(byte[] ciphertextWithNonce, byte[] key, byte[] associatedData)
    {
        byte[] nonce = ciphertextWithNonce.Take(12).ToArray();
        byte[] ciphertext = ciphertextWithNonce.Skip(12).ToArray();
        IBufferedCipher? cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce, associatedData));
        return cipher.DoFinal(ciphertext);
    }
}