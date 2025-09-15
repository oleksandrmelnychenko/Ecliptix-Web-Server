using System.Security.Cryptography;
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
using static Ecliptix.Domain.Memberships.OPAQUE.OpaqueConstants;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public static class OpaqueCryptoUtilities
{
    private static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName(CryptographicConstants.EllipticCurveName);

    public static readonly ECDomainParameters DomainParams =
        new(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H);

    private static readonly SecureRandom SecureRandomInstance = new();

    public static AsymmetricCipherKeyPair GenerateKeyPairFromSeed(byte[] seed)
    {
        BigInteger? d = new(1, seed);
        d = d.Mod(DomainParams.N.Subtract(BigInteger.One)).Add(BigInteger.One);

        Org.BouncyCastle.Math.EC.ECPoint q = DomainParams.G.Multiply(d).Normalize();
        ECPrivateKeyParameters privateKey = new(d, DomainParams);
        ECPublicKeyParameters publicKey = new(q, DomainParams);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    public static Result<byte[], OpaqueFailure> HkdfExtract(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt)
    {
        if (ikm.IsEmpty) return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput());

        HMac hmac = new(new Sha256Digest());
        byte[] saltBytes;

        if (salt.IsEmpty)
        {
            saltBytes = new byte[hmac.GetMacSize()];
        }
        else
        {
            saltBytes = salt.ToArray();
        }

        try
        {
            hmac.Init(new KeyParameter(saltBytes));

            byte[] ikmBytes = ikm.ToArray();
            hmac.BlockUpdate(ikmBytes, 0, ikm.Length);

            byte[] prk = new byte[hmac.GetMacSize()];
            hmac.DoFinal(prk, 0);

            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(ikmBytes);

            return Result<byte[], OpaqueFailure>.Ok(prk);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidKeySignature(ex.Message, ex));
        }
    }

    public static byte[] HkdfExpand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());

        byte[] prkBytes = prk.ToArray();
        byte[] infoBytes = info.ToArray();

        hkdf.Init(HkdfParameters.SkipExtractParameters(prkBytes, infoBytes));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);

        CryptographicOperations.ZeroMemory(prkBytes);
        CryptographicOperations.ZeroMemory(infoBytes);

        return okm;
    }

    public static byte[] DeriveKey(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int outputLength)
    {
        HkdfBytesGenerator hkdf = new(new Sha256Digest());

        byte[] ikmBytes = ikm.ToArray();
        byte[] infoBytes = info.ToArray();
        byte[]? saltBytes = salt.IsEmpty ? null : salt.ToArray();

        hkdf.Init(new HkdfParameters(ikmBytes, saltBytes, infoBytes));
        byte[] okm = new byte[outputLength];
        hkdf.GenerateBytes(okm, 0, outputLength);

        CryptographicOperations.ZeroMemory(ikmBytes);
        CryptographicOperations.ZeroMemory(infoBytes);
        if (saltBytes != null)
            CryptographicOperations.ZeroMemory(saltBytes);

        return okm;
    }

    public static Result<byte[], OpaqueFailure> StretchOprfOutput(ReadOnlySpan<byte> oprfOutput)
    {
        if (oprfOutput.IsEmpty)
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput("OPRF output cannot be empty"));

        try
        {
            byte[] oprfBytes = oprfOutput.ToArray();
            byte[] saltBytes = HkdfExpand(oprfOutput, HkdfInfoStrings.OpaqueSalt, Pbkdf2SaltLength);

            Serilog.Log.Debug("🔐 OPAQUE Server StretchOprfOutput: oprfOutput: {OprfOutput}", Convert.ToHexString(oprfBytes));
            Serilog.Log.Debug("🔐 OPAQUE Server StretchOprfOutput: derivedSalt: {Salt}", Convert.ToHexString(saltBytes));
            Serilog.Log.Debug("🔐 OPAQUE Server StretchOprfOutput: iterations: {Iterations}", Pbkdf2Iterations);

            using Rfc2898DeriveBytes pbkdf2 = new(
                oprfBytes,
                saltBytes,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256);

            byte[] stretched = pbkdf2.GetBytes(HashLength);

            Serilog.Log.Debug("🔐 OPAQUE Server StretchOprfOutput: stretchedKey: {StretchedKey}", Convert.ToHexString(stretched));

            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(oprfBytes);

            return Result<byte[], OpaqueFailure>.Ok(stretched);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"PBKDF2 failed: {ex.Message}"));
        }
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
            byte[] nonce = new byte[AesGcmNonceLengthBytes];
            SecureRandomInstance.NextBytes(nonce);

            AeadParameters cipherParams = new(new KeyParameter(key), AesGcmTagLengthBits, nonce,
                associatedData);
            cipher.Init(true, cipherParams);

            int outputSize = cipher.GetOutputSize(plaintext.Length);
            byte[] result = new byte[AesGcmNonceLengthBytes + outputSize];

            nonce.CopyTo(result, 0);

            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, result,
                AesGcmNonceLengthBytes);
            cipher.DoFinal(result, AesGcmNonceLengthBytes + len);

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

    public static Result<Unit, OpaqueFailure> ValidatePoint(Org.BouncyCastle.Math.EC.ECPoint point)
    {
        bool isValid = true;
        string errorMessage = string.Empty;

        bool infinityCheck = point.IsInfinity;
        if (infinityCheck)
        {
            isValid = false;
            errorMessage = ErrorMessages.PointAtInfinity;
        }

        bool validityCheck = point.IsValid();
        if (!validityCheck && isValid)
        {
            isValid = false;
            errorMessage = ErrorMessages.PointNotValid;
        }

        Org.BouncyCastle.Math.EC.ECPoint orderCheck = point.Multiply(DomainParams.N);
        bool subgroupCheck = orderCheck.IsInfinity;
        if (!subgroupCheck && isValid)
        {
            isValid = false;
            errorMessage = ErrorMessages.SubgroupCheckFailed;
        }

        if (!isValid)
        {
            Thread.SpinWait(100);

            if (infinityCheck)
                return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidPoint(ErrorMessages.PointAtInfinity));
            if (!validityCheck)
                return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidPoint(ErrorMessages.PointNotValid));
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.SubgroupCheckFailed(ErrorMessages.SubgroupCheckFailed));
        }

        return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
    }

    public static Result<byte[], OpaqueFailure> Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        try
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            Span<byte> nonce = stackalloc byte[AesGcmNonceLengthBytes];
            SecureRandomInstance.NextBytes(nonce);

            Span<byte> keyBuffer = stackalloc byte[key.Length];
            key.CopyTo(keyBuffer);

            byte[]? associatedDataArray = null;
            if (!associatedData.IsEmpty)
            {
                associatedDataArray = associatedData.ToArray();
            }

            AeadParameters cipherParams = new(new KeyParameter(keyBuffer.ToArray()), AesGcmTagLengthBits, nonce.ToArray(), associatedDataArray);
            cipher.Init(true, cipherParams);

            int outputSize = cipher.GetOutputSize(plaintext.Length);
            byte[] result = new byte[AesGcmNonceLengthBytes + outputSize];

            nonce.CopyTo(result.AsSpan(0, AesGcmNonceLengthBytes));

            byte[] plaintextBuffer = plaintext.ToArray();

            int len = cipher.ProcessBytes(plaintextBuffer, 0, plaintext.Length, result, AesGcmNonceLengthBytes);
            cipher.DoFinal(result, AesGcmNonceLengthBytes + len);

            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(keyBuffer);
            CryptographicOperations.ZeroMemory(plaintextBuffer);
            if (associatedDataArray != null)
                CryptographicOperations.ZeroMemory(associatedDataArray);

            return Result<byte[], OpaqueFailure>.Ok(result);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.EncryptFailed(ex.Message, ex));
        }
    }

    public static Result<byte[], OpaqueFailure> Decrypt(ReadOnlySpan<byte> ciphertextWithNonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertextWithNonce.Length < AesGcmNonceLengthBytes)
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.DecryptFailed());

        ReadOnlySpan<byte> nonce = ciphertextWithNonce[..AesGcmNonceLengthBytes];
        ReadOnlySpan<byte> ciphertext = ciphertextWithNonce[AesGcmNonceLengthBytes..];

        try
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");

            Span<byte> keyBuffer = stackalloc byte[key.Length];
            key.CopyTo(keyBuffer);

            Span<byte> nonceBuffer = stackalloc byte[nonce.Length];
            nonce.CopyTo(nonceBuffer);

            byte[]? associatedDataArray = null;
            if (!associatedData.IsEmpty)
            {
                associatedDataArray = associatedData.ToArray();
            }

            AeadParameters cipherParams = new(new KeyParameter(keyBuffer.ToArray()), AesGcmTagLengthBits, nonceBuffer.ToArray(), associatedDataArray);
            cipher.Init(false, cipherParams);

            byte[] ciphertextBuffer = ciphertext.ToArray();
            ciphertext.CopyTo(ciphertextBuffer);

            byte[] result = cipher.DoFinal(ciphertextBuffer);

            CryptographicOperations.ZeroMemory(keyBuffer);
            CryptographicOperations.ZeroMemory(nonceBuffer);
            CryptographicOperations.ZeroMemory(ciphertextBuffer);
            if (associatedDataArray != null)
                CryptographicOperations.ZeroMemory(associatedDataArray);

            return Result<byte[], OpaqueFailure>.Ok(result);
        }
        catch (InvalidCipherTextException ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.DecryptFailed(ex.Message, ex));
        }
    }

}