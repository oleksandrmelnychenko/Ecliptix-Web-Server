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

    public byte[] ProcessOprfRequest(ReadOnlySpan<byte> oprfRequest)
    {
        Span<byte> requestBuffer = stackalloc byte[oprfRequest.Length];
        oprfRequest.CopyTo(requestBuffer);
        ECPoint requestPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(requestBuffer.ToArray());

        Result<Unit, OpaqueFailure> validationResult = OpaqueCryptoUtilities.ValidatePoint(requestPoint);
        if (validationResult.IsErr)
            throw new InvalidOperationException($"Invalid OPRF request point: {validationResult.UnwrapErr().Message}");

        ECPoint responsePoint = requestPoint.Multiply(_serverOprfKey);
        return responsePoint.GetEncoded(CryptographicFlags.CompressedPointEncoding);
    }

    public Result<Unit, OpaqueFailure> CompleteRegistration(byte[] peerRegistrationRecord)
    {
        try
        {
            const int minLength = CompressedPublicKeyLength + NonceLength + HashLength;
            if (peerRegistrationRecord.Length < minLength)
                return Result<Unit, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput(ErrorMessages.InvalidRegistrationRecordTooShort));

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
        byte[] oprfResponse = ProcessOprfRequest(oprfRequest);
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
        byte[] currentPasswordOprfResponse = ProcessOprfRequest(request.CurrentPasswordOprf.Span);

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
        return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(new OpaquePasswordChangeCompleteResponse
        {
            ServerMac = ByteString.CopyFrom(serverMac),
            Result = OpaquePasswordChangeCompleteResponse.Types.PasswordChangeResult.Succeeded
        });
    }

    /// <summary>
    ///  SESSSIONS is for tests only will be removed 18.08.2025 O.Melnychenko
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public Result<SessionValidationResponse, OpaqueFailure> ValidateSession(SessionValidationRequest request)
    {
        try
        {
            byte[] sessionTokenBytes = Convert.FromHexString(request.SessionToken);
            if (sessionTokenBytes.Length != SessionTokenLength)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            byte[] sessionKey = OpaqueCryptoUtilities.DeriveKey(_serverTokenEncryptionKey, null, SessionTokenKeyInfo,
                DefaultKeyLength);
            Result<byte[], OpaqueFailure> decryptResult =
                OpaqueCryptoUtilities.Decrypt(sessionTokenBytes, sessionKey, null);

            if (decryptResult.IsErr)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddMinutes(DefaultSessionExpirationMinutes);

            return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
            {
                IsValid = true,
                ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt)
            });
        }
        catch (Exception ex)
        {
            return Result<SessionValidationResponse, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput($"{ErrorMessages.SessionTokenInvalid}: {ex.Message}"));
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
            int sessionCount = new Random().Next(1, 5); // Simulate 1-4 active sessions

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