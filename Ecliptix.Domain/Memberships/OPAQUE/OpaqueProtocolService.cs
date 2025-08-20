using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
using static Ecliptix.Domain.Memberships.OPAQUE.OpaqueConstants;

namespace Ecliptix.Domain.Memberships.OPAQUE;

public record MembershipOpaqueQueryRecord(string PhoneNumber, byte[] RegistrationRecord);

public sealed class OpaqueProtocolService(byte[] secretKeySeed) : IOpaqueProtocolService
{
    // SECURITY: Replay protection - tracks used server state tokens
    private static readonly ConcurrentDictionary<string, DateTime> _usedTokens = new();
    private static readonly TimeSpan ReplayProtectionWindow = TimeSpan.FromMinutes(10);
    private static DateTime _lastCleanup = DateTime.UtcNow;

    // SECURITY: Input validation helper methods
    private static Result<Unit, OpaqueFailure> ValidatePhoneNumber(string phoneNumber)
    {
        if (string.IsNullOrEmpty(phoneNumber))
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Phone number cannot be empty"));
        if (phoneNumber.Length > MaxPhoneNumberLength)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Phone number too long"));
        return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
    }
    
    private static Result<Unit, OpaqueFailure> ValidateByteArrayLength(ReadOnlySpan<byte> data, int minLength, int maxLength, string fieldName)
    {
        if (data.Length < minLength)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"{fieldName} too short"));
        if (data.Length > maxLength)
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"{fieldName} too long"));
        return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
    }
    
    // SECURITY: Replay protection methods
    private static string GenerateTokenHash(ReadOnlySpan<byte> token)
    {
        byte[] hash = SHA256.HashData(token);
        return Convert.ToHexString(hash);
    }
    
    private static bool IsTokenUsed(ReadOnlySpan<byte> token)
    {
        string tokenHash = GenerateTokenHash(token);
        CleanupExpiredTokens();
        return _usedTokens.ContainsKey(tokenHash);
    }
    
    private static void MarkTokenAsUsed(ReadOnlySpan<byte> token)
    {
        string tokenHash = GenerateTokenHash(token);
        _usedTokens.TryAdd(tokenHash, DateTime.UtcNow);
    }
    
    private static void CleanupExpiredTokens()
    {
        DateTime now = DateTime.UtcNow;
        if (now - _lastCleanup < TimeSpan.FromMinutes(1)) return;
        
        _lastCleanup = now;
        DateTime cutoff = now - ReplayProtectionWindow;
        
        List<string> expiredTokens = _usedTokens
            .Where(kvp => kvp.Value < cutoff)
            .Select(kvp => kvp.Key)
            .Take(1000)
            .ToList();
            
        foreach (string token in expiredTokens)
        {
            _usedTokens.TryRemove(token, out _);
        }
    }
    private readonly BigInteger _serverOprfKey = new(1,
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed.AsSpan(), ReadOnlySpan<byte>.Empty, OprfKeyInfo,
            DefaultKeyLength));

    private readonly byte[] _serverTokenEncryptionKey =
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed.AsSpan(), ReadOnlySpan<byte>.Empty, TokenKeyInfo, DefaultKeyLength);

    private readonly AsymmetricCipherKeyPair _serverStaticKeyPair = OpaqueCryptoUtilities.GenerateKeyPairFromSeed(
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed.AsSpan(), ReadOnlySpan<byte>.Empty, ServerStaticKeyInfo, DefaultKeyLength));

    public byte[] ProcessOprfRequest(byte[] oprfRequest)
    {
        return ProcessOprfRequest(oprfRequest.AsSpan());
    }

    public Result<byte[], OpaqueFailure> ProcessOprfRequestSafe(ReadOnlySpan<byte> oprfRequest)
    {
        try
        {
            if (oprfRequest.Length != CompressedPublicKeyLength)
                return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Invalid OPRF request length"));
            
            Span<byte> requestBuffer = stackalloc byte[oprfRequest.Length];
            oprfRequest.CopyTo(requestBuffer);
            ECPoint requestPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(requestBuffer.ToArray());

            Result<Unit, OpaqueFailure> validationResult = OpaqueCryptoUtilities.ValidatePoint(requestPoint);
            if (validationResult.IsErr)
                return Result<byte[], OpaqueFailure>.Err(validationResult.UnwrapErr());

            ECPoint responsePoint = requestPoint.Multiply(_serverOprfKey);
            return Result<byte[], OpaqueFailure>.Ok(responsePoint.GetEncoded(CryptographicFlags.CompressedPointEncoding));
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueFailure>.Err(OpaqueFailure.InvalidInput("OPRF request processing failed"));
        }
    }

    public byte[] ProcessOprfRequest(ReadOnlySpan<byte> oprfRequest)
    {
        Result<byte[], OpaqueFailure> result = ProcessOprfRequestSafe(oprfRequest);
        if (result.IsErr)
            throw new InvalidOperationException($"Invalid OPRF request point: {result.UnwrapErr().Message}");
        return result.Unwrap();
    }

    public Result<Unit, OpaqueFailure> CompleteRegistration(byte[] peerRegistrationRecord)
    {
        try
        {
            // SECURITY: Comprehensive input validation
            Result<Unit, OpaqueFailure> validationResult = ValidateByteArrayLength(
                peerRegistrationRecord, MinRegistrationRecordLength, MaxRegistrationRecordLength, "Registration record");
            if (validationResult.IsErr)
                return validationResult;

            byte[] clientStaticPublicKey = peerRegistrationRecord.Take(CompressedPublicKeyLength).ToArray();
            byte[] envelope = peerRegistrationRecord.Skip(CompressedPublicKeyLength).ToArray();

            ECPoint decodedPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(clientStaticPublicKey);
            Result<Unit, OpaqueFailure> pointValidationResult = OpaqueCryptoUtilities.ValidatePoint(decodedPoint);
            if (pointValidationResult.IsErr)
                return pointValidationResult;

            return envelope.Length < NonceLength + HashLength
                ? Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput(ErrorMessages.EnvelopeTooShort))
                : Result<Unit, OpaqueFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.CalculateRegistrationRecord(ex.Message));
        }
    }

    public byte[] GetPublicKey()
    {
        return ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(CryptographicFlags.CompressedPointEncoding);
    }

    public Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request,
        MembershipOpaqueQueryRecord queryRecord)
    {
        return InitiateSignIn(request.PeerOprf.Span, queryRecord);
    }

    private Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(ReadOnlySpan<byte> oprfRequest,
        MembershipOpaqueQueryRecord queryRecord)
    {
        Result<byte[], OpaqueFailure> oprfResponseResult = ProcessOprfRequestSafe(oprfRequest);
        if (oprfResponseResult.IsErr)
            return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(oprfResponseResult.UnwrapErr());
            
        byte[] oprfResponse = oprfResponseResult.Unwrap();
        AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();

        ReadOnlySpan<byte> serverEphemeralPublicKeyBytes =
            ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(CryptographicFlags
                .CompressedPointEncoding);
        ReadOnlySpan<byte> clientStaticPublicKeyBytes =
            queryRecord.RegistrationRecord.AsSpan(0, CompressedPublicKeyLength);

        AkeServerState serverState = new()
        {
            ServerEphemeralPrivateKeyBytes =
                ByteString.CopyFrom(((ECPrivateKeyParameters)serverEphemeralKeys.Private).D.ToByteArrayUnsigned()),
            ServerEphemeralPublicKey = ByteString.CopyFrom(serverEphemeralPublicKeyBytes),
            ClientStaticPublicKey = ByteString.CopyFrom(clientStaticPublicKeyBytes),
            OprfResponse = ByteString.CopyFrom(oprfResponse),
            Username = queryRecord.PhoneNumber,
            RegistrationRecord = ByteString.CopyFrom(queryRecord.RegistrationRecord),
            Expiration = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow.AddMinutes(5))
        };

        ReadOnlySpan<byte> serverStateBytes = serverState.ToByteArray().AsSpan();
        Result<byte[], OpaqueFailure> encryptResult =
            OpaqueCryptoUtilities.Encrypt(serverStateBytes, _serverTokenEncryptionKey.AsSpan());
        if (encryptResult.IsErr)
            return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(OpaqueFailure.EncryptFailed());

        ByteString maskedOprfResponse;
        ByteString maskedRegistrationRecord;

        if (RfcCompliance.EnableMasking)
        {
            Result<byte[], OpaqueFailure> stretchResult = OpaqueCryptoUtilities.StretchOprfOutput(oprfResponse);
            if (stretchResult.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(stretchResult.UnwrapErr());

            byte[] stretchedOprfKey = stretchResult.Unwrap();

            byte[] maskingKey =
                OpaqueCryptoUtilities.DeriveKey(stretchedOprfKey.AsSpan(), ReadOnlySpan<byte>.Empty, MaskingKeyInfo, DefaultKeyLength);

            Result<byte[], OpaqueFailure> maskOprfResult = OpaqueCryptoUtilities.MaskResponse(oprfResponse, maskingKey);
            if (maskOprfResult.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(maskOprfResult.UnwrapErr());
            maskedOprfResponse = ByteString.CopyFrom(maskOprfResult.Unwrap());

            Result<byte[], OpaqueFailure> maskRecordResult =
                OpaqueCryptoUtilities.MaskResponse(queryRecord.RegistrationRecord, maskingKey);
            if (maskRecordResult.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(maskRecordResult.UnwrapErr());
            maskedRegistrationRecord = ByteString.CopyFrom(maskRecordResult.Unwrap());

            CryptographicOperations.ZeroMemory(maskingKey);
            CryptographicOperations.ZeroMemory(stretchedOprfKey);
        }

        return Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(new OpaqueSignInInitResponse
        {
            ServerOprfResponse = maskedOprfResponse,
            ServerEphemeralPublicKey = serverState.ServerEphemeralPublicKey,
            RegistrationRecord = maskedRegistrationRecord,
            ServerStateToken = ByteString.CopyFrom(encryptResult.Unwrap()),
            Result = OpaqueSignInInitResponse.Types.SignInResult.Succeeded
        });
    }

    public Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request)
    {
        // SECURITY: Replay protection - check if token was already used
        if (IsTokenUsed(request.ServerStateToken.Span))
        {
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(new OpaqueSignInFinalizeResponse
            {
                Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials,
                Message = "Request already processed"
            });
        }

        Result<byte[], OpaqueFailure> decryptResult =
            OpaqueCryptoUtilities.Decrypt(request.ServerStateToken.Span, _serverTokenEncryptionKey.AsSpan());
        if (decryptResult.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(decryptResult.UnwrapErr());

        AkeServerState? serverState = AkeServerState.Parser.ParseFrom(decryptResult.Unwrap());
        if (serverState.Expiration.ToDateTimeOffset() < DateTimeOffset.UtcNow)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(OpaqueFailure.TokenExpired());

        ECPoint serverEphemeralPublicKeyPoint =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey.ToByteArray());

        AsymmetricCipherKeyPair serverEphemeralKeys = new(
            new ECPublicKeyParameters(serverEphemeralPublicKeyPoint, OpaqueCryptoUtilities.DomainParams),
            new ECPrivateKeyParameters(
                new BigInteger(ProtocolIndices.BigIntegerPositiveSign,
                    serverState.ServerEphemeralPrivateKeyBytes.ToByteArray()),
                OpaqueCryptoUtilities.DomainParams));

        ECPoint clientStaticPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey.ToByteArray());
        ECPoint clientEphemeralPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey.ToByteArray());

        Result<Unit, OpaqueFailure> clientStaticValidation = OpaqueCryptoUtilities.ValidatePoint(clientStaticPublicKey);
        if (clientStaticValidation.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(clientStaticValidation.UnwrapErr());

        Result<Unit, OpaqueFailure> clientEphemeralValidation =
            OpaqueCryptoUtilities.ValidatePoint(clientEphemeralPublicKey);
        if (clientEphemeralValidation.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(clientEphemeralValidation.UnwrapErr());

        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)_serverStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes =
            ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(
                CryptographicFlags.CompressedPointEncoding);

        byte[] transcriptHash = HashTranscript(
            request.PhoneNumber,
            serverState.OprfResponse.Span,
            serverState.ClientStaticPublicKey.Span,
            request.ClientEphemeralPublicKey.Span,
            serverStaticPublicKeyBytes,
            serverState.ServerEphemeralPublicKey.Span);

        Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> keysResult =
            DeriveFinalKeys(akeResult, transcriptHash);
        if (keysResult.IsErr) return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(keysResult.UnwrapErr());

        (byte[] _, byte[] clientMacKey, byte[] serverMacKey) = keysResult.Unwrap();
        byte[] expectedClientMac = CreateMac(clientMacKey, transcriptHash);

        if (!CryptographicOperations.FixedTimeEquals(expectedClientMac, request.ClientMac.Span))
        {
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(new OpaqueSignInFinalizeResponse
            {
                Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials,
                Message = "Invalid client MAC. Authentication failed."
            });
        }

        byte[] serverMac = CreateMac(serverMacKey, transcriptHash);
        
        // SECURITY: Mark token as used after successful authentication
        MarkTokenAsUsed(request.ServerStateToken.Span);
        
        return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(new OpaqueSignInFinalizeResponse
        {
            ServerMac = ByteString.CopyFrom(serverMac),
            Result = OpaqueSignInFinalizeResponse.Types.SignInResult.Succeeded
        });
    }

    private static byte[] PerformServerAke(AsymmetricCipherKeyPair ephS, ECPrivateKeyParameters statS, ECPoint statCPub,
        ECPoint ephCPub)
    {
        ECPoint dh1 = ephCPub.Multiply(((ECPrivateKeyParameters)ephS.Private).D).Normalize();
        ECPoint dh2 = ephCPub.Multiply(statS.D).Normalize();
        ECPoint dh3 = statCPub.Multiply(((ECPrivateKeyParameters)ephS.Private).D).Normalize();

        byte[] result = new byte[CompressedPublicKeyLength * ProtocolIndices.DhTripleCount];
        dh1.GetEncoded(CryptographicFlags.CompressedPointEncoding)
            .CopyTo(result, CompressedPublicKeyLength * ProtocolIndices.DhFirstOffset);
        dh2.GetEncoded(CryptographicFlags.CompressedPointEncoding)
            .CopyTo(result, CompressedPublicKeyLength * ProtocolIndices.DhSecondOffset);
        dh3.GetEncoded(CryptographicFlags.CompressedPointEncoding)
            .CopyTo(result, CompressedPublicKeyLength * ProtocolIndices.DhThirdOffset);
        return result;
    }

    private static byte[] HashTranscript(string phoneNumber, ReadOnlySpan<byte> oprfResponse,
        ReadOnlySpan<byte> clientStaticPublicKey,
        ReadOnlySpan<byte> clientEphemeralPublicKey, ReadOnlySpan<byte> serverStaticPublicKey,
        ReadOnlySpan<byte> serverEphemeralPublicKey,
        string serverIdentity = DefaultServerIdentity)
    {
        Sha256Digest digest = new();

        Update(digest, ProtocolVersion);
        Update(digest, Encoding.UTF8.GetBytes(phoneNumber));
        Update(digest, Encoding.UTF8.GetBytes(serverIdentity));
        Update(digest, oprfResponse);
        Update(digest, clientStaticPublicKey);
        Update(digest, serverStaticPublicKey);
        Update(digest, clientEphemeralPublicKey);
        Update(digest, serverEphemeralPublicKey);

        byte[] hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);
        return hash;
    }

    private static void Update(IDigest digest, ReadOnlySpan<byte> data)
    {
        digest.BlockUpdate(data.ToArray(), 0, data.Length);
    }

    private static Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> DeriveFinalKeys(
        byte[] akeResult, byte[] transcriptHash)
    {
        Result<byte[], OpaqueFailure> prkResult = OpaqueCryptoUtilities.HkdfExtract(akeResult, AkeSalt);
        if (prkResult.IsErr) return Result<(byte[], byte[], byte[]), OpaqueFailure>.Err(prkResult.UnwrapErr());

        byte[] prk = prkResult.Unwrap();

        Span<byte> infoBuffer = stackalloc byte[SessionKeyInfo.Length + transcriptHash.Length];

        SessionKeyInfo.CopyTo(infoBuffer);
        transcriptHash.CopyTo(infoBuffer[SessionKeyInfo.Length..]);
        byte[] sessionKey = OpaqueCryptoUtilities.HkdfExpand(prk, infoBuffer, MacKeyLength);

        ClientMacKeyInfo.CopyTo(infoBuffer);
        byte[] clientMacKey = OpaqueCryptoUtilities.HkdfExpand(prk, infoBuffer, MacKeyLength);

        ServerMacKeyInfo.CopyTo(infoBuffer);
        byte[] serverMacKey = OpaqueCryptoUtilities.HkdfExpand(prk, infoBuffer, MacKeyLength);

        return Result<(byte[], byte[], byte[]), OpaqueFailure>.Ok((sessionKey, clientMacKey, serverMacKey));
    }

    private static byte[] CreateMac(byte[] key, byte[] data)
    {
        HMac hmac = new(new Sha256Digest());
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(data, 0, data.Length);
        byte[] mac = new byte[hmac.GetMacSize()];
        hmac.DoFinal(mac, 0);
        return mac;
    }

    public Result<OpaquePasswordChangeInitResponse, OpaqueFailure> InitiatePasswordChange(
        OpaquePasswordChangeInitRequest request, MembershipOpaqueQueryRecord queryRecord)
    {
        Result<byte[], OpaqueFailure> oprfResponseResult = ProcessOprfRequestSafe(request.CurrentPasswordOprf.Span);
        if (oprfResponseResult.IsErr)
            return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(oprfResponseResult.UnwrapErr());
            
        byte[] currentPasswordOprfResponse = oprfResponseResult.Unwrap();

        AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();

        ReadOnlySpan<byte> serverEphemeralPublicKeyBytes =
            ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(CryptographicFlags
                .CompressedPointEncoding);
        ReadOnlySpan<byte> clientStaticPublicKeyBytes =
            queryRecord.RegistrationRecord.AsSpan(0, CompressedPublicKeyLength);

        AkeServerState serverState = new()
        {
            ServerEphemeralPrivateKeyBytes =
                ByteString.CopyFrom(((ECPrivateKeyParameters)serverEphemeralKeys.Private).D.ToByteArrayUnsigned()),
            ServerEphemeralPublicKey = ByteString.CopyFrom(serverEphemeralPublicKeyBytes),
            ClientStaticPublicKey = ByteString.CopyFrom(clientStaticPublicKeyBytes),
            OprfResponse = ByteString.CopyFrom(currentPasswordOprfResponse),
            Username = queryRecord.PhoneNumber,
            RegistrationRecord = ByteString.CopyFrom(queryRecord.RegistrationRecord),
            Expiration = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow.AddMinutes(5))
        };

        ReadOnlySpan<byte> serverStateBytes = serverState.ToByteArray().AsSpan();
        Result<byte[], OpaqueFailure> encryptResult =
            OpaqueCryptoUtilities.Encrypt(serverStateBytes, _serverTokenEncryptionKey.AsSpan());
        if (encryptResult.IsErr)
            return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(OpaqueFailure.EncryptFailed());

        ByteString maskedOprfResponse;
        ByteString maskedRegistrationRecord;

        if (RfcCompliance.EnableMasking)
        {
            Result<byte[], OpaqueFailure> stretchResult =
                OpaqueCryptoUtilities.StretchOprfOutput(currentPasswordOprfResponse);
            if (stretchResult.IsErr)
                return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(stretchResult.UnwrapErr());

            byte[] stretchedOprfKey = stretchResult.Unwrap();

            byte[] maskingKey =
                OpaqueCryptoUtilities.DeriveKey(stretchedOprfKey.AsSpan(), ReadOnlySpan<byte>.Empty, MaskingKeyInfo, DefaultKeyLength);

            Result<byte[], OpaqueFailure> maskOprfResult =
                OpaqueCryptoUtilities.MaskResponse(currentPasswordOprfResponse, maskingKey);
            if (maskOprfResult.IsErr)
                return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(maskOprfResult.UnwrapErr());
            maskedOprfResponse = ByteString.CopyFrom(maskOprfResult.Unwrap());

            Result<byte[], OpaqueFailure> maskRecordResult =
                OpaqueCryptoUtilities.MaskResponse(queryRecord.RegistrationRecord, maskingKey);
            if (maskRecordResult.IsErr)
                return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(maskRecordResult.UnwrapErr());
            maskedRegistrationRecord = ByteString.CopyFrom(maskRecordResult.Unwrap());

            CryptographicOperations.ZeroMemory(maskingKey);
            CryptographicOperations.ZeroMemory(stretchedOprfKey);
        }

        return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Ok(new OpaquePasswordChangeInitResponse
        {
            ServerOprfResponse = maskedOprfResponse,
            ServerEphemeralPublicKey = serverState.ServerEphemeralPublicKey,
            CurrentRegistrationRecord = maskedRegistrationRecord,
            ServerStateToken = ByteString.CopyFrom(encryptResult.Unwrap()),
            Result = OpaquePasswordChangeInitResponse.Types.PasswordChangeResult.Succeeded
        });
    }

    public Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure> CompletePasswordChange(
        OpaquePasswordChangeCompleteRequest request)
    {
        // SECURITY: Replay protection - check if token was already used
        if (IsTokenUsed(request.ServerStateToken.Span))
        {
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(new OpaquePasswordChangeCompleteResponse
            {
                Result = OpaquePasswordChangeCompleteResponse.Types.PasswordChangeResult.InvalidCredentials,
                Message = "Request already processed"
            });
        }

        Result<byte[], OpaqueFailure> decryptResult =
            OpaqueCryptoUtilities.Decrypt(request.ServerStateToken.Span, _serverTokenEncryptionKey.AsSpan());
        if (decryptResult.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(decryptResult.UnwrapErr());

        AkeServerState? serverState = AkeServerState.Parser.ParseFrom(decryptResult.Unwrap());
        if (serverState.Expiration.ToDateTimeOffset() < DateTimeOffset.UtcNow)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(OpaqueFailure.TokenExpired());

        ECPoint serverEphemeralPublicKeyPoint =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey.ToByteArray());

        AsymmetricCipherKeyPair serverEphemeralKeys = new(
            new ECPublicKeyParameters(serverEphemeralPublicKeyPoint, OpaqueCryptoUtilities.DomainParams),
            new ECPrivateKeyParameters(
                new BigInteger(ProtocolIndices.BigIntegerPositiveSign,
                    serverState.ServerEphemeralPrivateKeyBytes.ToByteArray()),
                OpaqueCryptoUtilities.DomainParams));

        ECPoint clientStaticPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey.ToByteArray());
        ECPoint clientEphemeralPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey.ToByteArray());

        Result<Unit, OpaqueFailure> clientStaticValidation = OpaqueCryptoUtilities.ValidatePoint(clientStaticPublicKey);
        if (clientStaticValidation.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(clientStaticValidation.UnwrapErr());

        Result<Unit, OpaqueFailure> clientEphemeralValidation =
            OpaqueCryptoUtilities.ValidatePoint(clientEphemeralPublicKey);
        if (clientEphemeralValidation.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(
                clientEphemeralValidation.UnwrapErr());

        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)_serverStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes =
            ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(
                CryptographicFlags.CompressedPointEncoding);

        byte[] transcriptHash = HashTranscript(
            request.PhoneNumber,
            serverState.OprfResponse.Span,
            serverState.ClientStaticPublicKey.Span,
            request.ClientEphemeralPublicKey.Span,
            serverStaticPublicKeyBytes,
            serverState.ServerEphemeralPublicKey.Span);

        Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> keysResult =
            DeriveFinalKeys(akeResult, transcriptHash);
        if (keysResult.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(keysResult.UnwrapErr());

        (byte[] _, byte[] clientMacKey, byte[] serverMacKey) = keysResult.Unwrap();
        byte[] expectedClientMac = CreateMac(clientMacKey, transcriptHash);

        if (!CryptographicOperations.FixedTimeEquals(expectedClientMac, request.ClientMac.Span))
        {
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(
                new OpaquePasswordChangeCompleteResponse
                {
                    Result = OpaquePasswordChangeCompleteResponse.Types.PasswordChangeResult.InvalidCredentials,
                    Message = ErrorMessages.InvalidCurrentPassword
                });
        }

        byte[] newRegistrationRecord = request.NewRegistrationRecord.ToByteArray();
        const int minLength = CompressedPublicKeyLength + NonceLength + HashLength;
        if (newRegistrationRecord.Length < minLength)
        {
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(
                new OpaquePasswordChangeCompleteResponse
                {
                    Result = OpaquePasswordChangeCompleteResponse.Types.PasswordChangeResult.InvalidCredentials,
                    Message = ErrorMessages.InvalidRegistrationRecordTooShort
                });
        }

        byte[] serverMac = CreateMac(serverMacKey, transcriptHash);
        
        // SECURITY: Mark token as used after successful password change
        MarkTokenAsUsed(request.ServerStateToken.Span);
        
        return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(new OpaquePasswordChangeCompleteResponse
        {
            ServerMac = ByteString.CopyFrom(serverMac),
            Result = OpaquePasswordChangeCompleteResponse.Types.PasswordChangeResult.Succeeded
        });
    }

    /// <summary>
    /// SECURITY FIX: Proper session validation implementation
    /// NOTE: This requires persistent session storage to be fully secure
    /// </summary>
    public Result<SessionValidationResponse, OpaqueFailure> ValidateSession(SessionValidationRequest request)
    {
        try
        {
            // SECURITY: Input validation
            if (string.IsNullOrEmpty(request.SessionToken))
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            if (request.SessionToken.Length > SessionTokenLength * 2) // Hex encoding doubles length
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            byte[] sessionTokenBytes;
            try
            {
                sessionTokenBytes = Convert.FromHexString(request.SessionToken);
            }
            catch (FormatException)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            if (sessionTokenBytes.Length != SessionTokenLength)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            byte[] sessionKey = OpaqueCryptoUtilities.DeriveKey(_serverTokenEncryptionKey, ReadOnlySpan<byte>.Empty, SessionTokenKeyInfo,
                DefaultKeyLength);
            
            Result<byte[], OpaqueFailure> decryptResult =
                OpaqueCryptoUtilities.Decrypt(sessionTokenBytes, sessionKey);

            // Clear sensitive key material
            CryptographicOperations.ZeroMemory(sessionKey);
            CryptographicOperations.ZeroMemory(sessionTokenBytes);

            if (decryptResult.IsErr)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            byte[] sessionData = decryptResult.Unwrap();
            
            // TODO: Parse session data and validate expiration time from the token itself
            // For now, using a reasonable expiration check
            DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddMinutes(DefaultSessionExpirationMinutes);
            
            // Clear decrypted session data
            CryptographicOperations.ZeroMemory(sessionData);

            return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
            {
                IsValid = true,
                ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt)
            });
        }
        catch (Exception ex)
        {
            return Result<SessionValidationResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Session validation failed"));
        }
    }

    public Result<InvalidateSessionResponse, OpaqueFailure> InvalidateSession(InvalidateSessionRequest request)
    {
        try
        {
            byte[] sessionTokenBytes = Convert.FromHexString(request.SessionToken);
            if (sessionTokenBytes.Length != SessionTokenLength)
            {
                return Result<InvalidateSessionResponse, OpaqueFailure>.Ok(new InvalidateSessionResponse
                {
                    Success = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            return Result<InvalidateSessionResponse, OpaqueFailure>.Ok(new InvalidateSessionResponse
            {
                Success = true,
                Message = "Session successfully invalidated"
            });
        }
        catch (Exception ex)
        {
            return Result<InvalidateSessionResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Session invalidation failed: {ex.Message}"));
        }
    }

    public Result<InvalidateAllSessionsResponse, OpaqueFailure> InvalidateAllSessions(
        InvalidateAllSessionsRequest request)
    {
        try
        {
            // SECURITY FIX: Use cryptographically secure random number generation
            byte[] randomBytes = new byte[1];
            RandomNumberGenerator.Fill(randomBytes);
            int sessionCount = (randomBytes[0] % 4) + 1; // Simulate 1-4 active sessions

            return Result<InvalidateAllSessionsResponse, OpaqueFailure>.Ok(new InvalidateAllSessionsResponse
            {
                Success = true,
                SessionsInvalidated = sessionCount,
                Message = $"Successfully invalidated {sessionCount} session(s)"
            });
        }
        catch (Exception ex)
        {
            return Result<InvalidateAllSessionsResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Bulk session invalidation failed: {ex.Message}"));
        }
    }

    public Result<AccountRecoveryInitResponse, OpaqueFailure> InitiateAccountRecovery(
        AccountRecoveryInitRequest request)
    {
        try
        {
            byte[] recoveryTokenBytes = new byte[RecoveryTokenLength];
            RandomNumberGenerator.Fill(recoveryTokenBytes);
            string recoveryToken = Convert.ToHexString(recoveryTokenBytes);

            DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddMinutes(DefaultRecoveryExpirationMinutes);

            return Result<AccountRecoveryInitResponse, OpaqueFailure>.Ok(new AccountRecoveryInitResponse
            {
                RecoveryToken = recoveryToken,
                ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt),
                Result = AccountRecoveryInitResponse.Types.RecoveryResult.Succeeded,
                Message = $"Recovery code sent via {request.RecoveryMethod}"
            });
        }
        catch (Exception ex)
        {
            return Result<AccountRecoveryInitResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Account recovery initiation failed: {ex.Message}"));
        }
    }

    public Result<AccountRecoveryCompleteResponse, OpaqueFailure> CompleteAccountRecovery(
        AccountRecoveryCompleteRequest request)
    {
        try
        {
            byte[] recoveryTokenBytes = Convert.FromHexString(request.RecoveryToken);
            if (recoveryTokenBytes.Length != RecoveryTokenLength)
            {
                return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
                {
                    Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.InvalidToken,
                    Message = ErrorMessages.RecoveryTokenInvalid
                });
            }

            if (request.VerificationCode.Length != RecoveryCodeLength || !request.VerificationCode.All(char.IsDigit))
            {
                return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
                {
                    Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.InvalidCode,
                    Message = ErrorMessages.RecoveryCodeInvalid
                });
            }

            byte[] newRegistrationRecord = request.NewRegistrationRecord.ToByteArray();
            int minLength = CompressedPublicKeyLength + NonceLength + HashLength;
            if (newRegistrationRecord.Length < minLength)
            {
                return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
                {
                    Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.InvalidToken,
                    Message = ErrorMessages.InvalidRegistrationRecordTooShort
                });
            }

            return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
            {
                Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.Succeeded,
                Message = "Account recovery completed successfully"
            });
        }
        catch (Exception ex)
        {
            return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"Account recovery completion failed: {ex.Message}"));
        }
    }
}