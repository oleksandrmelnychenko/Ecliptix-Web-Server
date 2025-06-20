using System.Text;
using Ecliptix.Core.AuthenticationSystem;
using Ecliptix.Domain.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Ecliptix.Core.OpaqueProtocol;

public class ClientPasswordAuthSystem
{
    private readonly AsymmetricKeyParameter _serverStaticPublicKey;

    public ClientPasswordAuthSystem(AsymmetricKeyParameter serverStaticPublicKey)
    {
        _serverStaticPublicKey =
            serverStaticPublicKey ?? throw new ArgumentNullException(nameof(serverStaticPublicKey));
    }

    public (byte[] OprfRequest, BigInteger Blind) CreateOprfRequest(string password)
    {
        var b = Encoding.UTF8.GetBytes(password);
        BigInteger blind = OpaqueCryptoUtilities.GenerateRandomScalar();
        Result<ECPoint, OpaqueFailure> p = OpaqueCryptoUtilities.HashToPoint(b);
        ECPoint oprfRequestPoint = p.Unwrap().Multiply(blind);
        return (oprfRequestPoint.GetEncoded(true), blind);
    }

    public byte[] CreateRegistrationRecord(string password, byte[] oprfResponse, BigInteger blind)
    {
        byte[] oprfKey = RecoverOprfKey(oprfResponse, blind);
        byte[] credentialKey = OpaqueCryptoUtilities.DeriveKey(oprfKey, null, "credential_key"u8.ToArray(), 32);
        AsymmetricCipherKeyPair clientStaticKeyPair = OpaqueCryptoUtilities.GenerateKeyPair();
        byte[] clientStaticPrivateKey = ((ECPrivateKeyParameters)clientStaticKeyPair.Private).D.ToByteArrayUnsigned();
        byte[] clientStaticPublicKey = ((ECPublicKeyParameters)clientStaticKeyPair.Public).Q.GetEncoded(true);
        byte[] ad = Encoding.UTF8.GetBytes(password);
        var envelope = OpaqueCryptoUtilities.Encrypt(clientStaticPrivateKey, credentialKey, ad);
        return clientStaticPublicKey.Concat(envelope.Unwrap()).ToArray();
    }

    public async Task<(OpaqueLoginFinalizeRequest Request, byte[] SessionKey)> FinalizeLoginAsync(
        string username,
        string password,
        OpaqueLoginInitResponse loginResponse,
        BigInteger blind,
        Func<OpaqueLoginFinalizeRequest, Task<Result<OpaqueLoginFinalizeResponse, string>>> serverFinalizeCallback)
    {
        byte[] oprfKey = RecoverOprfKey(loginResponse.OprfResponse, blind);
        byte[] credentialKey =
            OpaqueCryptoUtilities.DeriveKey(oprfKey, null, Encoding.UTF8.GetBytes("credential_key"), 32);

        byte[] clientStaticPublicKeyBytes = loginResponse.RegistrationRecord.Take(33).ToArray();
        byte[] envelope = loginResponse.RegistrationRecord.Skip(33).ToArray();

        Result<byte[], OpaqueFailure> clientStaticPrivateKeyBytes =
            OpaqueCryptoUtilities.Decrypt(envelope, credentialKey, Encoding.UTF8.GetBytes(password));
        ECPrivateKeyParameters clientStaticPrivateKey = new(new BigInteger(1, clientStaticPrivateKeyBytes.Unwrap()),
            OpaqueCryptoUtilities.DomainParams);

        AsymmetricCipherKeyPair clientEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();
        ECPoint serverStaticPublicKey = ((ECPublicKeyParameters)_serverStaticPublicKey).Q;
        ECPoint serverEphemeralPublicKey =
            OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(loginResponse.ServerEphemeralPublicKey);
        byte[] akeResult = PerformClientAke(clientEphemeralKeys, clientStaticPrivateKey, serverStaticPublicKey,
            serverEphemeralPublicKey);

        byte[] clientEphemeralPublicKeyBytes = ((ECPublicKeyParameters)clientEphemeralKeys.Public).Q.GetEncoded(true);
        byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)_serverStaticPublicKey).Q.GetEncoded(true);

        byte[] transcriptHash = HashTranscript(username, loginResponse.OprfResponse, clientStaticPublicKeyBytes,
            clientEphemeralPublicKeyBytes, serverStaticPublicKeyBytes, loginResponse.ServerEphemeralPublicKey);

        (byte[] sessionKey, byte[] clientMacKey) = DeriveFinalKeys(akeResult, transcriptHash);
        byte[] clientMac = CreateMac(clientMacKey, transcriptHash);

        OpaqueLoginFinalizeRequest request = new OpaqueLoginFinalizeRequest(username, clientEphemeralPublicKeyBytes,
            clientMac, loginResponse.ServerStateToken);

        // Verify login with server
        var loginResult = await serverFinalizeCallback(request);
        if (!loginResult.IsOk)
            throw new InvalidOperationException($"Login finalization failed: {loginResult.UnwrapErr()}");

        return (request, sessionKey);
    }

    public OpaquePasswordResetInitRequest InitiatePasswordReset(string username)
    {
        return new OpaquePasswordResetInitRequest(username);
    }

    public OpaquePasswordResetFinalizeRequest FinalizePasswordReset(string username, string resetToken,
        string newPassword, byte[] oprfResponse, BigInteger blind)
    {
        byte[] newRegistrationRecord = CreateRegistrationRecord(newPassword, oprfResponse, blind);
        return new OpaquePasswordResetFinalizeRequest(username, resetToken, newRegistrationRecord);
    }

    public async Task<OpaquePasswordChangeRequest> ChangePasswordAsync(
        string username,
        string currentPassword,
        string newPassword,
        byte[] newOprfResponse,
        BigInteger newBlind,
        Func<OpaqueLoginInitRequest, Task<OpaqueLoginInitResponse>> serverLoginInitCallback,
        Func<OpaqueLoginFinalizeRequest, Task<Result<OpaqueLoginFinalizeResponse, string>>> serverFinalizeCallback)
    {
        // Step 1: Authenticate with current password
        var (loginOprfRequest, loginBlind) = CreateOprfRequest(currentPassword);
        var loginInitResponse = await serverLoginInitCallback(new OpaqueLoginInitRequest(username, loginOprfRequest));
        var (loginFinalizeRequest, sessionKey) = await FinalizeLoginAsync(username, currentPassword, loginInitResponse,
            loginBlind, serverFinalizeCallback);

        // Step 2: Create new registration record for new password
        byte[] newRegistrationRecord = CreateRegistrationRecord(newPassword, newOprfResponse, newBlind);

        // Step 3: Create password change request
        return new OpaquePasswordChangeRequest(username, loginFinalizeRequest.ServerStateToken, newRegistrationRecord,
            loginFinalizeRequest.ClientEphemeralPublicKey);
    }

    private byte[] RecoverOprfKey(byte[] oprfResponse, BigInteger blind)
    {
        ECPoint oprfResponsePoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(oprfResponse);
        BigInteger blindInverse = blind.ModInverse(OpaqueCryptoUtilities.DomainParams.N);
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
        Sha256Digest digest = new Sha256Digest();

        void Update(byte[] data)
        {
            if (data != null) digest.BlockUpdate(data, 0, data.Length);
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
        byte[] salt = Encoding.UTF8.GetBytes("OPAQUE-AKE-Salt");
        var prkR = OpaqueCryptoUtilities.HkdfExtract(akeResult, salt);
        var prk = prkR.Unwrap();
        byte[] sessionKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("session_key").Concat(transcriptHash).ToArray(), 32);
        byte[] clientMacKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("client_mac_key").Concat(transcriptHash).ToArray(), 32);
        return (sessionKey, clientMacKey);
    }

    private byte[] CreateMac(byte[] key, byte[] data)
    {
        HMac hmac = new HMac(new Sha256Digest());
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(data, 0, data.Length);
        byte[] mac = new byte[hmac.GetMacSize()];
        hmac.DoFinal(mac, 0);
        return mac;
    }
}