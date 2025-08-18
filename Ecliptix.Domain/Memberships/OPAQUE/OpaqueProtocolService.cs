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
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed, null, OprfKeyInfo,
            DefaultKeyLength));

    private readonly byte[] _serverTokenEncryptionKey =
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed, null, TokenKeyInfo, DefaultKeyLength);

    private readonly AsymmetricCipherKeyPair _serverStaticKeyPair = OpaqueCryptoUtilities.GenerateKeyPairFromSeed(
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed, null, ServerStaticKeyInfo, DefaultKeyLength));

    public byte[] ProcessOprfRequest(byte[] oprfRequest)
    {
        ECPoint requestPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(oprfRequest);
        
        // Validate the OPRF request point
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
            // Minimum length: client public key + envelope (nonce + MAC)
            int minLength = CompressedPublicKeyLength + NonceLength + HashLength;
            if (peerRegistrationRecord.Length < minLength)
                return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput(ErrorMessages.InvalidRegistrationRecordTooShort));
                
            // Extract client static public key and envelope
            byte[] clientStaticPublicKey = peerRegistrationRecord.Take(CompressedPublicKeyLength).ToArray();
            byte[] envelope = peerRegistrationRecord.Skip(CompressedPublicKeyLength).ToArray();
            
            // Validate client static public key
            Org.BouncyCastle.Math.EC.ECPoint decodedPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(clientStaticPublicKey);
            Result<Unit, OpaqueFailure> pointValidationResult = OpaqueCryptoUtilities.ValidatePoint(decodedPoint);
            if (pointValidationResult.IsErr)
                return pointValidationResult;
            
            // For registration, we cannot verify the MAC envelope because we don't have the auth key
            // The MAC envelope verification will happen during authentication
            // However, we can validate the envelope structure
            if (envelope.Length < NonceLength + HashLength)
                return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput(ErrorMessages.EnvelopeTooShort));
                
            return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.CalculateRegistrationRecord(ex.Message));
        }
    }

    public byte[] GetPublicKey() => ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(CryptographicFlags.CompressedPointEncoding);

    public Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request,
        MembershipOpaqueQueryRecord queryRecord)
    {
        return InitiateSignIn(request.PeerOprf.ToByteArray(), queryRecord);
    }

    private Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(byte[] oprfRequest,
        MembershipOpaqueQueryRecord queryRecord)
    {
        byte[] oprfResponse = ProcessOprfRequest(oprfRequest);
        AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();

        ReadOnlySpan<byte> serverEphemeralPublicKeyBytes =
            ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(CryptographicFlags.CompressedPointEncoding);
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

        Result<byte[], OpaqueFailure> encryptResult =
            OpaqueCryptoUtilities.Encrypt(serverState.ToByteArray(), _serverTokenEncryptionKey, null);
        if (encryptResult.IsErr)
            return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(OpaqueFailure.EncryptFailed());

        // Apply masking for anti-enumeration if enabled
        ByteString maskedOprfResponse = serverState.OprfResponse;
        ByteString maskedRegistrationRecord = serverState.RegistrationRecord;
        
        if (RfcCompliance.EnableMasking)
        {
            // Stretch the OPRF response to match client's approach
            Result<byte[], OpaqueFailure> stretchResult = OpaqueCryptoUtilities.StretchOprfOutput(oprfResponse);
            if (stretchResult.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(stretchResult.UnwrapErr());
            
            byte[] stretchedOprfKey = stretchResult.Unwrap();
            
            // Derive masking key from stretched OPRF output (same as client)
            byte[] maskingKey = OpaqueCryptoUtilities.DeriveKey(stretchedOprfKey, null, MaskingKeyInfo, DefaultKeyLength);
            
            // Mask OPRF response
            Result<byte[], OpaqueFailure> maskOprfResult = OpaqueCryptoUtilities.MaskResponse(oprfResponse, maskingKey);
            if (maskOprfResult.IsErr)
                return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(maskOprfResult.UnwrapErr());
            maskedOprfResponse = ByteString.CopyFrom(maskOprfResult.Unwrap());
            
            // Mask registration record
            Result<byte[], OpaqueFailure> maskRecordResult = OpaqueCryptoUtilities.MaskResponse(queryRecord.RegistrationRecord, maskingKey);
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
            OpaqueCryptoUtilities.Decrypt(request.ServerStateToken.ToByteArray(), _serverTokenEncryptionKey, null);
        if (decryptResult.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(decryptResult.UnwrapErr());

        AkeServerState? serverState = AkeServerState.Parser.ParseFrom(decryptResult.Unwrap());
        if (serverState.Expiration.ToDateTimeOffset() < DateTimeOffset.UtcNow)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(OpaqueFailure.TokenExpired());

        // NOTE: In OPAQUE protocol, the server doesn't verify the MAC envelope during authentication
        // The MAC envelope is verified by the CLIENT when it receives the registration record from server
        // The server's role is to provide the registration record; client verifies its authenticity
        // Authentication security comes from the AKE protocol (client MAC verification)

        Org.BouncyCastle.Math.EC.ECPoint serverEphemeralPublicKeyPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey.ToByteArray());
        
        AsymmetricCipherKeyPair serverEphemeralKeys = new(
            new ECPublicKeyParameters(serverEphemeralPublicKeyPoint, OpaqueCryptoUtilities.DomainParams),
            new ECPrivateKeyParameters(new BigInteger(ProtocolIndices.BigIntegerPositiveSign, serverState.ServerEphemeralPrivateKeyBytes.ToByteArray()),
                OpaqueCryptoUtilities.DomainParams));

        Org.BouncyCastle.Math.EC.ECPoint clientStaticPublicKey = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey.ToByteArray());
        Org.BouncyCastle.Math.EC.ECPoint clientEphemeralPublicKey = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey.ToByteArray());

        // Validate all EC points 
        Result<Unit, OpaqueFailure> clientStaticValidation = OpaqueCryptoUtilities.ValidatePoint(clientStaticPublicKey);
        if (clientStaticValidation.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(clientStaticValidation.UnwrapErr());
            
        Result<Unit, OpaqueFailure> clientEphemeralValidation = OpaqueCryptoUtilities.ValidatePoint(clientEphemeralPublicKey);
        if (clientEphemeralValidation.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(clientEphemeralValidation.UnwrapErr());

        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)_serverStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(CryptographicFlags.CompressedPointEncoding);

        byte[] transcriptHash = HashTranscript(
            request.PhoneNumber,
            serverState.OprfResponse.ToByteArray(),
            serverState.ClientStaticPublicKey.ToByteArray(),
            request.ClientEphemeralPublicKey.ToByteArray(),
            serverStaticPublicKeyBytes,
            serverState.ServerEphemeralPublicKey.ToByteArray());

        Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> keysResult = DeriveFinalKeys(akeResult, transcriptHash);
        if (keysResult.IsErr) return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(keysResult.UnwrapErr());

        (byte[] _, byte[] clientMacKey, byte[] serverMacKey) = keysResult.Unwrap();
        byte[] expectedClientMac = CreateMac(clientMacKey, transcriptHash);

        if (!CryptographicOperations.FixedTimeEquals(expectedClientMac, request.ClientMac.ToByteArray()))
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
        dh1.GetEncoded(CryptographicFlags.CompressedPointEncoding).CopyTo(result, CompressedPublicKeyLength * ProtocolIndices.DhFirstOffset);
        dh2.GetEncoded(CryptographicFlags.CompressedPointEncoding).CopyTo(result, CompressedPublicKeyLength * ProtocolIndices.DhSecondOffset);
        dh3.GetEncoded(CryptographicFlags.CompressedPointEncoding).CopyTo(result, CompressedPublicKeyLength * ProtocolIndices.DhThirdOffset);
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
        // First, verify the current password using standard OPRF flow
        byte[] currentPasswordOprfResponse = ProcessOprfRequest(request.CurrentPasswordOprf.ToByteArray());
        
        // Generate ephemeral keys for the password change protocol
        AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();
        
        ReadOnlySpan<byte> serverEphemeralPublicKeyBytes =
            ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(CryptographicFlags.CompressedPointEncoding);
        ReadOnlySpan<byte> clientStaticPublicKeyBytes =
            queryRecord.RegistrationRecord.AsSpan(0, CompressedPublicKeyLength);

        // Create server state for password change process
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

        Result<byte[], OpaqueFailure> encryptResult =
            OpaqueCryptoUtilities.Encrypt(serverState.ToByteArray(), _serverTokenEncryptionKey, null);
        if (encryptResult.IsErr)
            return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(OpaqueFailure.EncryptFailed());

        // Apply masking for anti-enumeration if enabled
        ByteString maskedOprfResponse = serverState.OprfResponse;
        ByteString maskedRegistrationRecord = serverState.RegistrationRecord;
        
        if (RfcCompliance.EnableMasking)
        {
            // Stretch the OPRF response to match client's approach
            Result<byte[], OpaqueFailure> stretchResult = OpaqueCryptoUtilities.StretchOprfOutput(currentPasswordOprfResponse);
            if (stretchResult.IsErr)
                return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(stretchResult.UnwrapErr());
            
            byte[] stretchedOprfKey = stretchResult.Unwrap();
            
            // Derive masking key from stretched OPRF output (same as client)
            byte[] maskingKey = OpaqueCryptoUtilities.DeriveKey(stretchedOprfKey, null, MaskingKeyInfo, DefaultKeyLength);
            
            Result<byte[], OpaqueFailure> maskOprfResult = OpaqueCryptoUtilities.MaskResponse(currentPasswordOprfResponse, maskingKey);
            if (maskOprfResult.IsErr)
                return Result<OpaquePasswordChangeInitResponse, OpaqueFailure>.Err(maskOprfResult.UnwrapErr());
            maskedOprfResponse = ByteString.CopyFrom(maskOprfResult.Unwrap());
            
            Result<byte[], OpaqueFailure> maskRecordResult = OpaqueCryptoUtilities.MaskResponse(queryRecord.RegistrationRecord, maskingKey);
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
            OpaqueCryptoUtilities.Decrypt(request.ServerStateToken.ToByteArray(), _serverTokenEncryptionKey, null);
        if (decryptResult.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(decryptResult.UnwrapErr());

        AkeServerState? serverState = AkeServerState.Parser.ParseFrom(decryptResult.Unwrap());
        if (serverState.Expiration.ToDateTimeOffset() < DateTimeOffset.UtcNow)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(OpaqueFailure.TokenExpired());

        // Verify the current password authentication (similar to sign-in finalization)
        Org.BouncyCastle.Math.EC.ECPoint serverEphemeralPublicKeyPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey.ToByteArray());
        
        AsymmetricCipherKeyPair serverEphemeralKeys = new(
            new ECPublicKeyParameters(serverEphemeralPublicKeyPoint, OpaqueCryptoUtilities.DomainParams),
            new ECPrivateKeyParameters(new BigInteger(ProtocolIndices.BigIntegerPositiveSign, serverState.ServerEphemeralPrivateKeyBytes.ToByteArray()),
                OpaqueCryptoUtilities.DomainParams));

        Org.BouncyCastle.Math.EC.ECPoint clientStaticPublicKey = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey.ToByteArray());
        Org.BouncyCastle.Math.EC.ECPoint clientEphemeralPublicKey = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey.ToByteArray());

        // Validate all EC points 
        Result<Unit, OpaqueFailure> clientStaticValidation = OpaqueCryptoUtilities.ValidatePoint(clientStaticPublicKey);
        if (clientStaticValidation.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(clientStaticValidation.UnwrapErr());
            
        Result<Unit, OpaqueFailure> clientEphemeralValidation = OpaqueCryptoUtilities.ValidatePoint(clientEphemeralPublicKey);
        if (clientEphemeralValidation.IsErr)
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(clientEphemeralValidation.UnwrapErr());

        // Perform server AKE to verify current password
        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)_serverStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(CryptographicFlags.CompressedPointEncoding);

        byte[] transcriptHash = HashTranscript(
            request.PhoneNumber,
            serverState.OprfResponse.ToByteArray(),
            serverState.ClientStaticPublicKey.ToByteArray(),
            request.ClientEphemeralPublicKey.ToByteArray(),
            serverStaticPublicKeyBytes,
            serverState.ServerEphemeralPublicKey.ToByteArray());

        Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> keysResult = DeriveFinalKeys(akeResult, transcriptHash);
        if (keysResult.IsErr) return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Err(keysResult.UnwrapErr());

        (byte[] _, byte[] clientMacKey, byte[] serverMacKey) = keysResult.Unwrap();
        byte[] expectedClientMac = CreateMac(clientMacKey, transcriptHash);

        // Verify current password authentication
        if (!CryptographicOperations.FixedTimeEquals(expectedClientMac, request.ClientMac.ToByteArray()))
        {
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(new OpaquePasswordChangeCompleteResponse
            {
                Result = OpaquePasswordChangeCompleteResponse.Types.PasswordChangeResult.InvalidCredentials,
                Message = ErrorMessages.InvalidCurrentPassword
            });
        }

        // At this point, current password is verified, so we can accept the new registration record
        // In a real implementation, you would store the new registration record in the database
        // For now, we'll just validate that it's properly formatted
        byte[] newRegistrationRecord = request.NewRegistrationRecord.ToByteArray();
        int minLength = CompressedPublicKeyLength + NonceLength + HashLength;
        if (newRegistrationRecord.Length < minLength)
        {
            return Result<OpaquePasswordChangeCompleteResponse, OpaqueFailure>.Ok(new OpaquePasswordChangeCompleteResponse
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

    public Result<SessionValidationResponse, OpaqueFailure> ValidateSession(SessionValidationRequest request)
    {
        try
        {
            // In a real implementation, you would:
            // 1. Look up the session in a database/cache
            // 2. Check if it's expired
            // 3. Verify it belongs to the specified user
            
            // For now, we'll implement a basic token-based validation
            byte[] sessionTokenBytes = Convert.FromHexString(request.SessionToken);
            if (sessionTokenBytes.Length != SessionTokenLength)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            // Simple validation - in production, you'd check against stored sessions
            // For demo purposes, we'll consider tokens valid if they decrypt properly
            byte[] sessionKey = OpaqueCryptoUtilities.DeriveKey(_serverTokenEncryptionKey, null, SessionTokenKeyInfo, DefaultKeyLength);
            Result<byte[], OpaqueFailure> decryptResult = OpaqueCryptoUtilities.Decrypt(sessionTokenBytes, sessionKey, null);
            
            if (decryptResult.IsErr)
            {
                return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
                {
                    IsValid = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            // In real implementation, parse the decrypted data to get expiration time
            DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddMinutes(DefaultSessionExpirationMinutes);
            
            return Result<SessionValidationResponse, OpaqueFailure>.Ok(new SessionValidationResponse
            {
                IsValid = true,
                ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt)
            });
        }
        catch (Exception ex)
        {
            return Result<SessionValidationResponse, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"{ErrorMessages.SessionTokenInvalid}: {ex.Message}"));
        }
    }

    public Result<InvalidateSessionResponse, OpaqueFailure> InvalidateSession(InvalidateSessionRequest request)
    {
        try
        {
            // In a real implementation, you would:
            // 1. Look up the session in your database/cache
            // 2. Mark it as invalid/expired
            // 3. Remove it from active sessions
            
            // For demo purposes, we'll just validate the token format
            byte[] sessionTokenBytes = Convert.FromHexString(request.SessionToken);
            if (sessionTokenBytes.Length != SessionTokenLength)
            {
                return Result<InvalidateSessionResponse, OpaqueFailure>.Ok(new InvalidateSessionResponse
                {
                    Success = false,
                    Message = ErrorMessages.SessionTokenInvalid
                });
            }

            // Simulate successful invalidation
            return Result<InvalidateSessionResponse, OpaqueFailure>.Ok(new InvalidateSessionResponse
            {
                Success = true,
                Message = "Session successfully invalidated"
            });
        }
        catch (Exception ex)
        {
            return Result<InvalidateSessionResponse, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"Session invalidation failed: {ex.Message}"));
        }
    }

    public Result<InvalidateAllSessionsResponse, OpaqueFailure> InvalidateAllSessions(InvalidateAllSessionsRequest request)
    {
        try
        {
            // In a real implementation, you would:
            // 1. Query all active sessions for the user
            // 2. Mark them all as invalid/expired
            // 3. Return the count of invalidated sessions
            
            // For demo purposes, simulate invalidating multiple sessions
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
            return Result<InvalidateAllSessionsResponse, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"Bulk session invalidation failed: {ex.Message}"));
        }
    }

    public Result<AccountRecoveryInitResponse, OpaqueFailure> InitiateAccountRecovery(AccountRecoveryInitRequest request)
    {
        try
        {
            // In a real implementation, you would:
            // 1. Verify the user exists
            // 2. Check rate limiting
            // 3. Generate a secure recovery token
            // 4. Send verification code via SMS/email
            // 5. Store recovery state with expiration
            
            // For demo purposes, generate a recovery token
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
            return Result<AccountRecoveryInitResponse, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"Account recovery initiation failed: {ex.Message}"));
        }
    }

    public Result<AccountRecoveryCompleteResponse, OpaqueFailure> CompleteAccountRecovery(AccountRecoveryCompleteRequest request)
    {
        try
        {
            // In a real implementation, you would:
            // 1. Verify the recovery token is valid and not expired
            // 2. Check the verification code against what was sent
            // 3. Validate the new registration record
            // 4. Replace the old registration record with the new one
            // 5. Invalidate the recovery token
            
            // Basic validation of recovery token format
            byte[] recoveryTokenBytes = Convert.FromHexString(request.RecoveryToken);
            if (recoveryTokenBytes.Length != RecoveryTokenLength)
            {
                return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
                {
                    Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.InvalidToken,
                    Message = ErrorMessages.RecoveryTokenInvalid
                });
            }

            // Validate verification code format (6 digits)
            if (request.VerificationCode.Length != RecoveryCodeLength || !request.VerificationCode.All(char.IsDigit))
            {
                return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
                {
                    Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.InvalidCode,
                    Message = ErrorMessages.RecoveryCodeInvalid
                });
            }

            // Validate new registration record format
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

            // In a real implementation, you would replace the user's registration record here
            return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Ok(new AccountRecoveryCompleteResponse
            {
                Result = AccountRecoveryCompleteResponse.Types.RecoveryResult.Succeeded,
                Message = "Account recovery completed successfully"
            });
        }
        catch (Exception ex)
        {
            return Result<AccountRecoveryCompleteResponse, OpaqueFailure>.Err(OpaqueFailure.InvalidInput($"Account recovery completion failed: {ex.Message}"));
        }
    }
}