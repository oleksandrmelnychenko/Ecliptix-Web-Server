using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ecliptix.Domain.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Ecliptix.Core.AuthenticationSystem;

public record UserOpaqueRecord(string Username, byte[] RegistrationRecord);

public record OpaqueRegInitRequest(string Username, byte[] OprfRequest);

public record OpaqueRegFinalizeRequest(string Username, byte[] RegistrationRecord);

public record OpaqueLoginInitRequest(string Username, byte[] OprfRequest);

public record OpaqueLoginInitResponse(
    byte[] OprfResponse,
    byte[] ServerEphemeralPublicKey,
    byte[] RegistrationRecord,
    byte[] ServerStateToken);

public record OpaqueLoginFinalizeRequest(
    string Username,
    byte[] ClientEphemeralPublicKey,
    byte[] ClientMac,
    byte[] ServerStateToken);

public record OpaqueLoginFinalizeResponse(byte[] ServerMac);

public class ServerPasswordAuthSystem
{
    public AsymmetricCipherKeyPair ServerStaticKeyPair { get; }
    private readonly BigInteger _serverOprfKey;
    private readonly byte[] _serverTokenEncryptionKey;

    public ServerPasswordAuthSystem(byte[] serverSecretSeed)
    {
        if (serverSecretSeed == null || serverSecretSeed.Length < 32)
            throw new ArgumentException("Server secret seed must be at least 32 bytes.");
        _serverOprfKey = new BigInteger(1,
            OpaqueCrypto.DeriveKey(serverSecretSeed, null, Encoding.UTF8.GetBytes("oprf_key"), 32));
        _serverTokenEncryptionKey =
            OpaqueCrypto.DeriveKey(serverSecretSeed, null, Encoding.UTF8.GetBytes("token_key"), 32);
        ServerStaticKeyPair = OpaqueCrypto.GenerateKeyPair();
    }


    public byte[] ProcessOprfRequest(byte[] oprfRequest)
    {
        ECPoint requestPoint = OpaqueCrypto.DomainParams.Curve.DecodePoint(oprfRequest);
        ECPoint responsePoint = requestPoint.Multiply(_serverOprfKey);
        return responsePoint.GetEncoded(true);
    }

    public Result<OpaqueLoginInitResponse, string> CreateLoginResponse(string username, byte[] oprfRequest,
        UserOpaqueRecord userRecord)
    {
        try
        {
            byte[] oprfResponse = ProcessOprfRequest(oprfRequest);
            AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCrypto.GenerateKeyPair();
            byte[] serverEphemeralPublicKeyBytes =
                ((ECPublicKeyParameters)serverEphemeralKeys.Public).Q.GetEncoded(true);

            AkeServerState serverState = new AkeServerState
            {
                ServerEphemeralPrivateKey =
                    ((ECPrivateKeyParameters)serverEphemeralKeys.Private).D.ToByteArrayUnsigned(),
                ServerEphemeralPublicKey = serverEphemeralPublicKeyBytes,
                ClientStaticPublicKey = userRecord.RegistrationRecord.Take(33).ToArray(),
                OprfResponse = oprfResponse,
                Username = username,
                RegistrationRecord = userRecord.RegistrationRecord,
                Expiration = DateTimeOffset.UtcNow.AddMinutes(5)
            };

            byte[] encryptedStateToken = OpaqueCrypto.AeadEncrypt(JsonSerializer.SerializeToUtf8Bytes(serverState),
                _serverTokenEncryptionKey, null);
            return Result<OpaqueLoginInitResponse, string>.Ok(new OpaqueLoginInitResponse(oprfResponse,
                serverEphemeralPublicKeyBytes, userRecord.RegistrationRecord, encryptedStateToken));
        }
        catch (Exception ex)
        {
            return Result<OpaqueLoginInitResponse, string>.Err(
                $"An internal error occurred while creating the login response: {ex.Message}");
        }
    }

    public Result<OpaqueLoginFinalizeResponse, string> VerifyLoginFinalization(OpaqueLoginFinalizeRequest request)
    {
        AkeServerState serverState;
        try
        {
            serverState = DecryptStateToken(request.ServerStateToken);
            if (serverState.Expiration < DateTimeOffset.UtcNow)
                return Result<OpaqueLoginFinalizeResponse, string>.Err("Invalid or expired login state token.");
        }
        catch (Exception)
        {
            return Result<OpaqueLoginFinalizeResponse, string>.Err(
                "Failed to decrypt state token. Tampering detected.");
        }

        AsymmetricCipherKeyPair serverEphemeralKeys = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey),
                OpaqueCrypto.DomainParams),
            new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKey),
                OpaqueCrypto.DomainParams));

        ECPoint clientStaticPublicKey = OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey);
        ECPoint clientEphemeralPublicKey =
            OpaqueCrypto.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey);

        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)ServerStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)ServerStaticKeyPair.Public).Q.GetEncoded(true);

        byte[] transcriptHash = HashTranscript(request.Username, serverState.OprfResponse,
            serverState.ClientStaticPublicKey,
            request.ClientEphemeralPublicKey, serverStaticPublicKeyBytes, serverState.ServerEphemeralPublicKey);

        (byte[] _, byte[] clientMacKey, byte[] serverMacKey) = DeriveFinalKeys(akeResult, transcriptHash);
        byte[] expectedClientMac = CreateMac(clientMacKey, transcriptHash);

        if (!CryptographicOperations.FixedTimeEquals(expectedClientMac, request.ClientMac))
            return Result<OpaqueLoginFinalizeResponse, string>.Err("Invalid client MAC. Authentication failed.");

        byte[] serverMac = CreateMac(serverMacKey, transcriptHash);
        return Result<OpaqueLoginFinalizeResponse, string>.Ok(new OpaqueLoginFinalizeResponse(serverMac));
    }

    private AkeServerState DecryptStateToken(byte[] serverStateToken)
    {
        byte[] decryptedState = OpaqueCrypto.AeadDecrypt(serverStateToken, _serverTokenEncryptionKey, null);
        return JsonSerializer.Deserialize<AkeServerState>(decryptedState);
    }

    private byte[] PerformServerAke(AsymmetricCipherKeyPair eph_s, ECPrivateKeyParameters stat_s, ECPoint stat_c_pub,
        ECPoint eph_c_pub)
    {
        ECPoint dh1 = eph_c_pub.Multiply(((ECPrivateKeyParameters)eph_s.Private).D).Normalize();
        ECPoint dh2 = eph_c_pub.Multiply(stat_s.D).Normalize();
        ECPoint dh3 = stat_c_pub.Multiply(((ECPrivateKeyParameters)eph_s.Private).D).Normalize();
        return dh1.GetEncoded(true).Concat(dh2.GetEncoded(true)).Concat(dh3.GetEncoded(true)).ToArray();
    }

    private byte[] HashTranscript(string username, byte[] oprfResponse, byte[] clientStaticPublicKey,
        byte[] clientEphemeralPublicKey, byte[] serverStaticPublicKey, byte[] serverEphemeralPublicKey)
    {
        Sha256Digest digest = new();

        void Update(byte[] data)
        {
            if (data != null) digest.BlockUpdate(data, 0, data.Length);
        }

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
    }

    private (byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey) DeriveFinalKeys(byte[] akeResult,
        byte[] transcriptHash)
    {
        byte[] salt = "OPAQUE-AKE-Salt"u8.ToArray();
        byte[] prk = OpaqueCrypto.HkdfExtract(akeResult, salt);
        byte[] sessionKey = OpaqueCrypto.HkdfExpand(prk,
            "session_key"u8.ToArray().Concat(transcriptHash).ToArray(), 32);
        byte[] clientMacKey = OpaqueCrypto.HkdfExpand(prk,
            "client_mac_key"u8.ToArray().Concat(transcriptHash).ToArray(), 32);
        byte[] serverMacKey = OpaqueCrypto.HkdfExpand(prk,
            "server_mac_key"u8.ToArray().Concat(transcriptHash).ToArray(), 32);
        return (sessionKey, clientMacKey, serverMacKey);
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

#if DEBUG
    public byte[] GetServerSessionKeyForTest(OpaqueLoginFinalizeRequest request)
    {
        AkeServerState serverState = DecryptStateToken(request.ServerStateToken);
        AsymmetricCipherKeyPair serverEphemeralKeys = new(
            new ECPublicKeyParameters(OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey),
                OpaqueCrypto.DomainParams),
            new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKey),
                OpaqueCrypto.DomainParams));
        ECPoint clientStaticPublicKey = OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey);
        ECPoint clientEphemeralPublicKey =
            OpaqueCrypto.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey);
        byte[] akeResult = PerformServerAke(serverEphemeralKeys, (ECPrivateKeyParameters)ServerStaticKeyPair.Private,
            clientStaticPublicKey, clientEphemeralPublicKey);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)ServerStaticKeyPair.Public).Q.GetEncoded(true);
        byte[] transcriptHash = HashTranscript(request.Username, serverState.OprfResponse,
            serverState.ClientStaticPublicKey,
            request.ClientEphemeralPublicKey, serverStaticPublicKeyBytes, serverState.ServerEphemeralPublicKey);
        (byte[] sessionKey, _, _) = DeriveFinalKeys(akeResult, transcriptHash);
        return sessionKey;
    }
#endif
}