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

namespace Ecliptix.Domain.Memberships.OPAQUE;

public record MembershipOpaqueQueryRecord(string PhoneNumber, byte[] RegistrationRecord);

public sealed class OpaqueProtocolService(byte[] secretKeySeed) : IOpaqueProtocolService
{
    private readonly BigInteger _serverOprfKey = new(1,
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed, null, OprfKeyInfo, DefaultOprfKeyLength));

    private readonly byte[] _serverTokenEncryptionKey =
        OpaqueCryptoUtilities.DeriveKey(secretKeySeed, null, TokenKeyInfo, DefaultOprfKeyLength);

    private readonly AsymmetricCipherKeyPair _serverStaticKeyPair = OpaqueCryptoUtilities.GenerateKeyPair();

    private static readonly byte[] OprfKeyInfo = "oprf_key"u8.ToArray();
    private static readonly byte[] TokenKeyInfo = "token_key"u8.ToArray();
    private static readonly byte[] AkeSalt = "OPAQUE-AKE-Salt"u8.ToArray();

    private const int DefaultOprfKeyLength = 32;
    private const int MacKeyLength = 32;


    public byte[] ProcessOprfRequest(byte[] oprfRequest)
    {
        ECPoint requestPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(oprfRequest);
        ECPoint responsePoint = requestPoint.Multiply(_serverOprfKey);
        return responsePoint.GetEncoded(true);
    }

    public Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(OpaqueSignInInitRequest request,
        MembershipOpaqueQueryRecord queryRecord)
    {
        return InitiateSignIn(request.PeerOprf.ToByteArray(), queryRecord);
    }

    public Result<Unit, OpaqueFailure> CompleteRegistration(
        byte[] peerRegistrationRecord)
    {
        const int expectedPublicKeyLength = 33;
        if (peerRegistrationRecord.Length < expectedPublicKeyLength)
            return Result<Unit, OpaqueFailure>.Err(
                OpaqueFailure.InvalidInput("Invalid registration record: too short."));

        try
        {
            byte[] clientStaticPublicKey = peerRegistrationRecord.Take(expectedPublicKeyLength).ToArray();
            ECPoint decodedPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(clientStaticPublicKey);
            if (!decodedPoint.IsValid())
                return Result<Unit, OpaqueFailure>.Err(
                    OpaqueFailure.InvalidInput("Invalid client static public key."));
            
            return Result<Unit, OpaqueFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueFailure>.Err(
                OpaqueFailure.CalculateRegistrationRecord(ex.Message));
        }
    }

    public byte[] GetPublicKey()
    {
        return ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(true);
    }

    public Result<OpaqueSignInInitResponse, OpaqueFailure> InitiateSignIn(byte[] oprfRequest,
        MembershipOpaqueQueryRecord queryRecord)
    {
        byte[] oprfResponse = ProcessOprfRequest(oprfRequest);
        AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();
        byte[] serverEphemeralPublicKeyBytes =
            ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(true);
        byte[] serverEphemeralPrivateKeyBytes =
            ((ECPrivateKeyParameters)serverEphemeralKeys.Private).D.ToByteArrayUnsigned();

        AkeServerState serverState = new()
        {
            ServerEphemeralPrivateKeyBytes = ByteString.CopyFrom(serverEphemeralPrivateKeyBytes),
            ServerEphemeralPublicKey = ByteString.CopyFrom(serverEphemeralPublicKeyBytes),
            ClientStaticPublicKey = ByteString.CopyFrom(queryRecord.RegistrationRecord.Take(33).ToArray()),
            OprfResponse = ByteString.CopyFrom(oprfResponse),
            Username = queryRecord.PhoneNumber,
            RegistrationRecord = ByteString.CopyFrom(queryRecord.RegistrationRecord),
            Expiration = Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow.AddMinutes(5))
        };

        Result<byte[], OpaqueFailure> encryptResult =
            OpaqueCryptoUtilities.Encrypt(serverState.ToByteArray(), _serverTokenEncryptionKey, null);
        if (encryptResult.IsErr)
            return Result<OpaqueSignInInitResponse, OpaqueFailure>.Err(OpaqueFailure.EncryptFailed());

        byte[] serverStateToken = encryptResult.Unwrap();

        return Result<OpaqueSignInInitResponse, OpaqueFailure>.Ok(new OpaqueSignInInitResponse
        {
            ServerOprfResponse = ByteString.CopyFrom(oprfResponse),
            ServerEphemeralPublicKey = ByteString.CopyFrom(serverEphemeralPublicKeyBytes),
            RegistrationRecord = ByteString.CopyFrom(queryRecord.RegistrationRecord),
            ServerStateToken = ByteString.CopyFrom(serverStateToken)
        });
    }

    public Result<OpaqueSignInFinalizeResponse, OpaqueFailure> FinalizeSignIn(OpaqueSignInFinalizeRequest request)
    {
        Result<byte[], OpaqueFailure> decryptResult = OpaqueCryptoUtilities.Decrypt(
            request.ServerStateToken.ToByteArray(),
            _serverTokenEncryptionKey, null);
        if (decryptResult.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(decryptResult.UnwrapErr());

        byte[] decryptedState = decryptResult.Unwrap();
        AkeServerState serverState = AkeServerState.Parser.ParseFrom(decryptedState);

        if (serverState.Expiration.ToDateTimeOffset() < DateTimeOffset.UtcNow)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(OpaqueFailure.EncryptFailed());

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

        byte[] akeResult = PerformServerAke(serverEphemeralKeys,
            (ECPrivateKeyParameters)_serverStaticKeyPair.Private, clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(true);

        byte[] transcriptHash = HashTranscript(
            request.PhoneNumber.ToString()!,
            serverState.OprfResponse.ToByteArray(),
            serverState.ClientStaticPublicKey.ToByteArray(),
            request.ClientEphemeralPublicKey.ToByteArray(),
            serverStaticPublicKeyBytes,
            serverState.ServerEphemeralPublicKey.ToByteArray());

        Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> keysResult =
            DeriveFinalKeys(akeResult, transcriptHash);
        if (keysResult.IsErr)
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Err(keysResult.UnwrapErr());

        (byte[] sessionKey, byte[] clientMacKey, byte[] serverMacKey) = keysResult.Unwrap();
        byte[] expectedClientMac = CreateMac(clientMacKey, transcriptHash);

        if (!CryptographicOperations.FixedTimeEquals(expectedClientMac, request.ClientMac.ToByteArray()))
            return Result<OpaqueSignInFinalizeResponse, OpaqueFailure>.Ok(new OpaqueSignInFinalizeResponse
            {
                Result = OpaqueSignInFinalizeResponse.Types.SignInResult.InvalidCredentials,
                ErrorMessage = "Invalid client MAC. Authentication failed."
            });

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
        return dh1.GetEncoded(true).Concat(dh2.GetEncoded(true)).Concat(dh3.GetEncoded(true)).ToArray();
    }

    private static byte[] HashTranscript(string username, byte[] oprfResponse, byte[] clientStaticPublicKey,
        byte[] clientEphemeralPublicKey, byte[] serverStaticPublicKey, byte[] serverEphemeralPublicKey)
    {
        Sha256Digest digest = new();

        Update("Ecliptix-OPAQUE-v1"u8.ToArray());
        Update(Encoding.UTF8.GetBytes(username));
        Update(oprfResponse);
        Update(clientStaticPublicKey);
        Update(clientEphemeralPublicKey);
        Update(serverStaticPublicKey);
        Update(serverEphemeralPublicKey);

        byte[] hash = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash, 0);
        return hash;

        void Update(byte[] data)
        {
            digest.BlockUpdate(data, 0, data.Length);
        }
    }

    private static Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure> DeriveFinalKeys(
        byte[] akeResult, byte[] transcriptHash)
    {
        Result<byte[], OpaqueFailure> prkResult = OpaqueCryptoUtilities.HkdfExtract(akeResult, AkeSalt);
        if (prkResult.IsErr)
            return Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure>.Err(
                prkResult.UnwrapErr());

        byte[] prk = prkResult.Unwrap();
        byte[] sessionKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            "session_key"u8.ToArray().Concat(transcriptHash).ToArray(), MacKeyLength);
        byte[] clientMacKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            "client_mac_key"u8.ToArray().Concat(transcriptHash).ToArray(), MacKeyLength);
        byte[] serverMacKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            "server_mac_key"u8.ToArray().Concat(transcriptHash).ToArray(), MacKeyLength);

        return Result<(byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey), OpaqueFailure>.Ok((sessionKey,
            clientMacKey, serverMacKey));
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