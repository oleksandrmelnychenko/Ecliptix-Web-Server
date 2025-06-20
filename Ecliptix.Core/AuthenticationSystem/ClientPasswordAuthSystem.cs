using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Ecliptix.Core.AuthenticationSystem;

public class ClientPasswordAuthSystem(AsymmetricKeyParameter staticPublicKey)
{
    public (byte[] OprfRequest, BigInteger Blind) CreateOprfRequest(string password)
    {
        BigInteger blind = OpaqueCrypto.GenerateRandomScalar();
        ECPoint p = OpaqueCrypto.HashToPoint(password);
        ECPoint oprfRequestPoint = p.Multiply(blind);
        return (oprfRequestPoint.GetEncoded(true), blind);
    }

    public byte[] CreateRegistrationRecord(string password, byte[] oprfResponse, BigInteger blind)
    {
        byte[] oprfKey = RecoverOprfKey(oprfResponse, blind);
        byte[] credentialKey = OpaqueCrypto.DeriveKey(oprfKey, null, Encoding.UTF8.GetBytes("credential_key"), 32);
        AsymmetricCipherKeyPair clientStaticKeyPair = OpaqueCrypto.GenerateKeyPair();
        byte[] clientStaticPrivateKey = ((ECPrivateKeyParameters)clientStaticKeyPair.Private).D.ToByteArrayUnsigned();
        byte[] clientStaticPublicKey = ((ECPublicKeyParameters)clientStaticKeyPair.Public).Q.GetEncoded(true);
        byte[] ad = Encoding.UTF8.GetBytes(password);
        byte[] envelope = OpaqueCrypto.AeadEncrypt(clientStaticPrivateKey, credentialKey, ad);
        return clientStaticPublicKey.Concat(envelope).ToArray();
    }

    public (OpaqueLoginFinalizeRequest Request, byte[] SessionKey) FinalizeLogin(string username, string password,
        OpaqueLoginInitResponse loginResponse, BigInteger blind)
    {
        byte[] oprfKey = RecoverOprfKey(loginResponse.OprfResponse, blind);
        byte[] credentialKey = OpaqueCrypto.DeriveKey(oprfKey, null, Encoding.UTF8.GetBytes("credential_key"), 32);

        byte[] clientStaticPublicKeyBytes = loginResponse.RegistrationRecord.Take(33).ToArray();
        byte[] envelope = loginResponse.RegistrationRecord.Skip(33).ToArray();

        byte[] clientStaticPrivateKeyBytes =
            OpaqueCrypto.AeadDecrypt(envelope, credentialKey, Encoding.UTF8.GetBytes(password));
        ECPrivateKeyParameters clientStaticPrivateKey =
            new(new BigInteger(1, clientStaticPrivateKeyBytes), OpaqueCrypto.DomainParams);

        AsymmetricCipherKeyPair clientEphemeralKeys = OpaqueCrypto.GenerateKeyPair();
        ECPoint serverStaticPublicKey = ((ECPublicKeyParameters)staticPublicKey).Q;
        ECPoint serverEphemeralPublicKey =
            OpaqueCrypto.DomainParams.Curve.DecodePoint(loginResponse.ServerEphemeralPublicKey);
        byte[] akeResult = PerformClientAke(clientEphemeralKeys, clientStaticPrivateKey, serverStaticPublicKey,
            serverEphemeralPublicKey);

        byte[] clientEphemeralPublicKeyBytes = ((ECPublicKeyParameters)clientEphemeralKeys.Public).Q.GetEncoded(true);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)staticPublicKey).Q.GetEncoded(true);

        byte[] transcriptHash = HashTranscript(username, loginResponse.OprfResponse, clientStaticPublicKeyBytes,
            clientEphemeralPublicKeyBytes, serverStaticPublicKeyBytes, loginResponse.ServerEphemeralPublicKey);

        (byte[] sessionKey, byte[] clientMacKey) = DeriveFinalKeys(akeResult, transcriptHash);
        byte[] clientMac = CreateMac(clientMacKey, transcriptHash);

        OpaqueLoginFinalizeRequest request = new OpaqueLoginFinalizeRequest(username, clientEphemeralPublicKeyBytes,
            clientMac, loginResponse.ServerStateToken);
        return (request, sessionKey);
    }

    private byte[] RecoverOprfKey(byte[] oprfResponse, BigInteger blind)
    {
        ECPoint oprfResponsePoint = OpaqueCrypto.DomainParams.Curve.DecodePoint(oprfResponse);
        BigInteger blindInverse = blind.ModInverse(OpaqueCrypto.DomainParams.N);
        return oprfResponsePoint.Multiply(blindInverse).GetEncoded(true);
    }

    private byte[] PerformClientAke(AsymmetricCipherKeyPair eph_c, ECPrivateKeyParameters stat_c, ECPoint stat_s_pub,
        ECPoint eph_s_pub)
    {
        ECPoint dh1 = eph_s_pub.Multiply(((ECPrivateKeyParameters)eph_c.Private).D).Normalize();
        ECPoint dh2 = stat_s_pub.Multiply(((ECPrivateKeyParameters)eph_c.Private).D).Normalize();
        ECPoint dh3 = eph_s_pub.Multiply(stat_c.D).Normalize();
        return dh1.GetEncoded(true).Concat(dh2.GetEncoded(true)).Concat(dh3.GetEncoded(true)).ToArray();
    }

    private byte[] HashTranscript(string username, byte[] oprfResponse, byte[] clientStaticPublicKey,
        byte[] clientEphemeralPublicKey, byte[] serverStaticPublicKey, byte[] serverEphemeralPublicKey)
    {
        Sha256Digest digest = new();

        void Update(byte[] data)
        {
            digest.BlockUpdate(data, 0, data.Length);
        }

        Update(Encoding.UTF8.GetBytes("Ecliptix-OPAQUE-v1"));
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

    private (byte[] SessionKey, byte[] ClientMacKey) DeriveFinalKeys(byte[] akeResult, byte[] transcriptHash)
    {
        byte[] salt = "OPAQUE-AKE-Salt"u8.ToArray();
        byte[] prk = OpaqueCrypto.HkdfExtract(akeResult, salt);
        byte[] sessionKey = OpaqueCrypto.HkdfExpand(prk,
            "session_key"u8.ToArray().Concat(transcriptHash).ToArray(), 32);
        byte[] clientMacKey = OpaqueCrypto.HkdfExpand(prk,
            "client_mac_key"u8.ToArray().Concat(transcriptHash).ToArray(), 32);
        return (sessionKey, clientMacKey);
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