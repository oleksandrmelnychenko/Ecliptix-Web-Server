// Ecliptix.Core.OpaqueProtocol.OpaqueCryptoUtilities.cs

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
// Assuming your Result type is here

namespace Ecliptix.Domain.Memberships.OPAQUE;

public static class OpaqueCryptoUtilities
{
    private static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName("secp256r1");
    public static readonly ECDomainParameters DomainParams = new(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H);
    
    // [PERF] Keep the ThreadLocal pool for digests. It's a great pattern.
    private static readonly ThreadLocal<Sha256Digest> DigestPool = new(() => new Sha256Digest());
    private static readonly SecureRandom SecureRandomInstance = new();

    // [FIX] New method to deterministically generate the server's static key pair from a seed.
    // This ensures the server has a persistent identity across restarts.
    public static AsymmetricCipherKeyPair GenerateKeyPairFromSeed(byte[] seed)
    {
        // Use the seed to derive a private key scalar 'd'.
        // We must ensure 'd' is within the valid range [1, N-1].
        var d = new BigInteger(1, seed);
        d = d.Mod(DomainParams.N.Subtract(BigInteger.One)).Add(BigInteger.One);

        ECPoint q = DomainParams.G.Multiply(d).Normalize();
        var privateKey = new ECPrivateKeyParameters(d, DomainParams);
        var publicKey = new ECPublicKeyParameters(q, DomainParams);
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
    
    public static Result<byte[], OpaqueFailure> HkdfExtract(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt)
    {
        if (ikm.IsEmpty) return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput());

        HMac hmac = new(new Sha256Digest());
        // Use an all-zero salt if not provided, as per RFC 5869.
        ReadOnlySpan<byte> effectiveSalt = salt.IsEmpty ? stackalloc byte[hmac.GetMacSize()] : salt;

        try
        {
            hmac.Init(new KeyParameter(effectiveSalt.ToArray())); // ToArray() is unavoidable here for BC API
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
    
    // [PERF] Use ReadOnlySpan to avoid array allocations for the 'info' parameter.
    public static byte[] HkdfExpand(byte[] prk, ReadOnlySpan<byte> info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(HkdfParameters.SkipExtractParameters(prk, info.ToArray())); // ToArray() is for BC API
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);
        return okm;
    }

    public static byte[] DeriveKey(byte[] ikm, byte[]? salt, ReadOnlySpan<byte> info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm, salt, info.ToArray())); // ToArray() is for BC API
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
            digest.Update(counter);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            BigInteger x = new(1, hash);
            // This is a simplified hash-to-curve attempt. For production, a more robust
            // standard like "try-and-increment" is acceptable but be aware of alternatives.
            if (x.SignValue > 0 && x.CompareTo(DomainParams.Curve.Field.Characteristic) < 0)
            {
                try
                {
                    ECPoint point = DomainParams.Curve.DecodePoint(DecompressPoint(x, 0x02)).Normalize();
                    if (point.IsValid()) return Result<ECPoint, OpaqueFailure>.Ok(point);
                }
                catch { /* Ignore and try next */ }
            }
            counter++;
        }

        return Result<ECPoint, OpaqueFailure>.Err(OpaqueFailure.HashingValidPointFailed());
    }

    // Helper for a simple hash-to-curve attempt
    private static byte[] DecompressPoint(BigInteger x, byte sign)
    {
        byte[] xBytes = x.ToByteArrayUnsigned();
        byte[] compressed = new byte[xBytes.Length + 1];
        compressed[0] = sign;
        Buffer.BlockCopy(xBytes, 0, compressed, 1, xBytes.Length);
        return compressed;
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
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(DomainParams, SecureRandomInstance));
        return generator.GenerateKeyPair();
    }

    // [PERF] Optimized Encrypt to minimize array copying.
    public static Result<byte[], OpaqueFailure> Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData)
    {
        try
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            byte[] nonce = new byte[OpaqueConstants.AesGcmNonceLengthBytes];
            SecureRandomInstance.NextBytes(nonce);
            
            var cipherParams = new AeadParameters(new KeyParameter(key), OpaqueConstants.AesGcmTagLengthBits, nonce, associatedData);
            cipher.Init(true, cipherParams);
            
            int outputSize = cipher.GetOutputSize(plaintext.Length);
            byte[] result = new byte[OpaqueConstants.AesGcmNonceLengthBytes + outputSize];
            
            // Write nonce to the start of the result buffer
            nonce.CopyTo(result, 0);
            
            // Perform encryption directly into the result buffer at the correct offset
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, result, OpaqueConstants.AesGcmNonceLengthBytes);
            cipher.DoFinal(result, OpaqueConstants.AesGcmNonceLengthBytes + len);
            
            return Result<byte[], OpaqueFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.EncryptFailed(ex.Message, ex));
        }
    }
    
    // [PERF] Optimized Decrypt to use spans and avoid intermediate arrays.
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
            var cipherParams = new AeadParameters(new KeyParameter(key), OpaqueConstants.AesGcmTagLengthBits, nonce.ToArray(), associatedData);
            cipher.Init(false, cipherParams);
            
            return Result<byte[], OpaqueFailure>.Ok(cipher.DoFinal(ciphertext.ToArray()));
        }
        catch (InvalidCipherTextException ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.DecryptFailed(ex.Message, ex));
        }
    }
}