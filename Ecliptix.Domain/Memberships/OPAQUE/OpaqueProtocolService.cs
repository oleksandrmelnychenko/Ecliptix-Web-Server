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
        ECPoint responsePoint = requestPoint.Multiply(_serverOprfKey);
        return responsePoint.GetEncoded(true);
    }

    public Result<Unit, OpaqueFailure> CompleteRegistration(byte[] peerRegistrationRecord)
    {
        try
        {
            byte[] clientStaticPublicKey = peerRegistrationRecord.Take(CompressedPublicKeyLength).ToArray();
            ECPoint decodedPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(clientStaticPublicKey);
            return !decodedPoint.IsValid()
                ? Result<Unit, OpaqueFailure>.Err(OpaqueFailure.InvalidInput("Invalid client static public key."))
                : Result<Unit, OpaqueFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueFailure>.Err(OpaqueFailure.CalculateRegistrationRecord(ex.Message));
        }
    }

    public byte[] GetPublicKey() => ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(true);

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
            ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(true);
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

        return Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(new OpaqueSignInInitResponse
        {
            ServerOprfResponse = serverState.OprfResponse,
            ServerEphemeralPublicKey = serverState.ServerEphemeralPublicKey,
            RegistrationRecord = serverState.RegistrationRecord,
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

        AsymmetricCipherKeyPair serverEphemeralKeys = new(
            new ECPublicKeyParameters(
                OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey
                    .ToByteArray()), OpaqueCryptoUtilities.DomainParams),
            new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKeyBytes.ToByteArray()),
                OpaqueCryptoUtilities.DomainParams));

        ECPoint clientStaticPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey.ToByteArray());
        ECPoint clientEphemeralPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey.ToByteArray());

        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)_serverStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(true);

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

        byte[] result = new byte[CompressedPublicKeyLength * 3];
        dh1.GetEncoded(true).CopyTo(result, 0);
        dh2.GetEncoded(true).CopyTo(result, CompressedPublicKeyLength);
        dh3.GetEncoded(true).CopyTo(result, CompressedPublicKeyLength * 2);
        return result;
    }

    private static byte[] HashTranscript(string phoneNumber, ReadOnlySpan<byte> oprfResponse,
        ReadOnlySpan<byte> clientStaticPublicKey,
        ReadOnlySpan<byte> clientEphemeralPublicKey, ReadOnlySpan<byte> serverStaticPublicKey,
        ReadOnlySpan<byte> serverEphemeralPublicKey)
    {
        Sha256Digest digest = new();

        Update(digest, ProtocolVersion);
        Update(digest, Encoding.UTF8.GetBytes(phoneNumber)); 
        Update(digest, oprfResponse);
        Update(digest, clientStaticPublicKey);
        Update(digest, clientEphemeralPublicKey);
        Update(digest, serverStaticPublicKey);
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
}