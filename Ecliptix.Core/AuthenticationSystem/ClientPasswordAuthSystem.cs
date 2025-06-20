using System.Text;
using Ecliptix.Domain.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Ecliptix.Core.AuthenticationSystem;

public class ClientPasswordAuthSystem
{
    private readonly AsymmetricKeyParameter _serverStaticPublicKey;
    private ServerPasswordAuthSystem _mockServer;
    private MockUserRepository _mockRepo;

    public ClientPasswordAuthSystem(AsymmetricKeyParameter serverStaticPublicKey)
    {
        _serverStaticPublicKey =
            serverStaticPublicKey ?? throw new ArgumentNullException(nameof(serverStaticPublicKey));
    }

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
            new ECPrivateKeyParameters(new BigInteger(1, clientStaticPrivateKeyBytes), OpaqueCrypto.DomainParams);

        AsymmetricCipherKeyPair clientEphemeralKeys = OpaqueCrypto.GenerateKeyPair();
        ECPoint serverStaticPublicKey = ((ECPublicKeyParameters)_serverStaticPublicKey).Q;
        ECPoint serverEphemeralPublicKey =
            OpaqueCrypto.DomainParams.Curve.DecodePoint(loginResponse.ServerEphemeralPublicKey);
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

    public async Task<OpaquePasswordChangeRequest> ChangePasswordAsync(string username, string currentPassword,
        string newPassword, byte[] newOprfResponse, BigInteger newBlind)
    {
        // Step 1: Authenticate with current password to get session key
        var (loginOprfRequest, loginBlind) = CreateOprfRequest(currentPassword);
        var loginInitResponse = await CallServerLoginInitAsync(username, loginOprfRequest);
        var (loginFinalizeRequest, sessionKey) =
            FinalizeLogin(username, currentPassword, loginInitResponse, loginBlind);

        // Capture the client ephemeral public key and server state token
        byte[] clientEphemeralPublicKeyBytes = loginFinalizeRequest.ClientEphemeralPublicKey;
        byte[] serverStateToken = loginFinalizeRequest.ServerStateToken;

        // Verify login with server
        var loginResult = await CallServerLoginFinalizeAsync(loginFinalizeRequest);
        if (!loginResult.IsOk)
            throw new InvalidOperationException($"Failed to authenticate: {loginResult.UnwrapErr()}");

        // Step 2: Create new registration record for new password
        byte[] newRegistrationRecord = CreateRegistrationRecord(newPassword, newOprfResponse, newBlind);

        // Step 3: Create password change request
        return new OpaquePasswordChangeRequest(username, serverStateToken, newRegistrationRecord,
            clientEphemeralPublicKeyBytes);
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
        byte[] prk = OpaqueCrypto.HkdfExtract(akeResult, salt);
        byte[] sessionKey = OpaqueCrypto.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("session_key").Concat(transcriptHash).ToArray(), 32);
        byte[] clientMacKey = OpaqueCrypto.HkdfExpand(prk,
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

    // Test helper to set up mock server
#if DEBUG
    public void SetServerMock(ServerPasswordAuthSystem server, MockUserRepository repo)
    {
        _mockServer = server;
        _mockRepo = repo;
    }

    private async Task<OpaqueLoginInitResponse> CallServerLoginInitAsync(string username, byte[] oprfRequest)
    {
        if (_mockServer == null || _mockRepo == null)
            throw new InvalidOperationException("Mock server not set up.");

        var user = await _mockRepo.GetUserByUsernameAsync(username);
        if (user == null)
            throw new InvalidOperationException("User not found.");

        var result = _mockServer.CreateLoginResponse(username, oprfRequest, user);
        return result.IsOk ? result.Unwrap() : throw new InvalidOperationException(result.UnwrapErr());
    }

    private async Task<Result<OpaqueLoginFinalizeResponse, string>> CallServerLoginFinalizeAsync(
        OpaqueLoginFinalizeRequest request)
    {
        if (_mockServer == null)
            throw new InvalidOperationException("Mock server not set up.");

        return _mockServer.VerifyLoginFinalization(request);
    }
#endif
}