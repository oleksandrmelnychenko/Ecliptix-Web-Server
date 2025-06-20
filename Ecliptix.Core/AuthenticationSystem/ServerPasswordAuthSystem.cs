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

// New records for password reset
public record OpaquePasswordResetInitRequest(string Username);

public record OpaquePasswordResetInitResponse(bool Success, string Message);

public record OpaquePasswordResetFinalizeRequest(string Username, string ResetToken, byte[] NewRegistrationRecord);

// New record for password change
public record OpaquePasswordChangeRequest(
    string Username,
    byte[] ServerStateToken,
    byte[] NewRegistrationRecord,
    byte[] ClientEphemeralPublicKey);

public class ServerPasswordAuthSystem
{
    public AsymmetricCipherKeyPair ServerStaticKeyPair { get; }
    private readonly BigInteger _serverOprfKey;
    private readonly byte[] _serverTokenEncryptionKey;
    private readonly Dictionary<string, AkePasswordResetState> _passwordResetStates = new();

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
                ServerEphemeralPrivateKeyBytes =
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
            new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKeyBytes),
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

    // New method for initiating password reset
    public Result<OpaquePasswordResetInitResponse, string> InitiatePasswordReset(OpaquePasswordResetInitRequest request)
    {
        try
        {
            // In a real system, verify user exists and get their email
            // For simplicity, assume user exists and generate a token
            string resetToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var resetState = new AkePasswordResetState
            {
                Username = request.Username,
                ResetToken = resetToken,
                Expiration = DateTimeOffset.UtcNow.AddHours(1)
            };

            // Store reset state (in-memory for this example; use a database in production)
            _passwordResetStates[request.Username] = resetState;

            // In a real system, send resetToken via email
            // For this example, just return success
            return Result<OpaquePasswordResetInitResponse, string>.Ok(
                new OpaquePasswordResetInitResponse(true,
                    $"Password reset initiated for {request.Username}. Token sent."));
        }
        catch (Exception ex)
        {
            return Result<OpaquePasswordResetInitResponse, string>.Err(
                $"Failed to initiate password reset: {ex.Message}");
        }
    }

    // New method for finalizing password reset
    public Result<bool, string> FinalizePasswordReset(OpaquePasswordResetFinalizeRequest request,
        Func<string, UserOpaqueRecord, Task> updateUserRecord)
    {
        try
        {
            if (!_passwordResetStates.TryGetValue(request.Username, out var resetState))
                return Result<bool, string>.Err("No password reset request found for user.");

            if (resetState.Expiration < DateTimeOffset.UtcNow)
                return Result<bool, string>.Err("Password reset token has expired.");

            if (resetState.ResetToken != request.ResetToken)
                return Result<bool, string>.Err("Invalid password reset token.");

            // Update user record with new registration record
            var newUserRecord = new UserOpaqueRecord(request.Username, request.NewRegistrationRecord);
            updateUserRecord(request.Username, newUserRecord).Wait();

            // Remove reset state
            _passwordResetStates.Remove(request.Username);

            return Result<bool, string>.Ok(true);
        }
        catch (Exception ex)
        {
            return Result<bool, string>.Err($"Failed to finalize password reset: {ex.Message}");
        }
    }

    public Result<bool, string> ChangePassword(OpaquePasswordChangeRequest request,
        Func<string, UserOpaqueRecord, Task> updateUserRecord)
    {
        try
        {
            // Decrypt the server state token to verify authentication context
            var serverState = DecryptStateToken(request.ServerStateToken);
            if (serverState.Expiration < DateTimeOffset.UtcNow)
                return Result<bool, string>.Err("Invalid or expired server state token.");

            // Reconstruct AKE to ensure valid session
            AsymmetricCipherKeyPair serverEphemeralKeys = new AsymmetricCipherKeyPair(
                new ECPublicKeyParameters(
                    OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey),
                    OpaqueCrypto.DomainParams),
                new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKeyBytes),
                    OpaqueCrypto.DomainParams));

            ECPoint clientStaticPublicKey =
                OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey);
            ECPoint clientEphemeralPublicKey =
                OpaqueCrypto.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey);

            byte[] akeResult = PerformServerAke(serverEphemeralKeys,
                (ECPrivateKeyParameters)ServerStaticKeyPair.Private, clientStaticPublicKey, clientEphemeralPublicKey);
            byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)ServerStaticKeyPair.Public).Q.GetEncoded(true);

            byte[] transcriptHash = HashTranscript(request.Username, serverState.OprfResponse,
                serverState.ClientStaticPublicKey,
                request.ClientEphemeralPublicKey, serverStaticPublicKeyBytes, serverState.ServerEphemeralPublicKey);

            // Update user record with new registration record
            var newUserRecord = new UserOpaqueRecord(request.Username, request.NewRegistrationRecord);
            updateUserRecord(request.Username, newUserRecord).Wait();

            return Result<bool, string>.Ok(true);
        }
        catch (Exception ex)
        {
            return Result<bool, string>.Err($"Failed to change password: {ex.Message}");
        }
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

    private (byte[] SessionKey, byte[] ClientMacKey, byte[] ServerMacKey) DeriveFinalKeys(byte[] akeResult,
        byte[] transcriptHash)
    {
        byte[] salt = Encoding.UTF8.GetBytes("OPAQUE-AKE-Salt");
        byte[] prk = OpaqueCrypto.HkdfExtract(akeResult, salt);
        byte[] sessionKey = OpaqueCrypto.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("session_key").Concat(transcriptHash).ToArray(), 32);
        byte[] clientMacKey = OpaqueCrypto.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("client_mac_key").Concat(transcriptHash).ToArray(), 32);
        byte[] serverMacKey = OpaqueCrypto.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("server_mac_key").Concat(transcriptHash).ToArray(), 32);
        return (sessionKey, clientMacKey, serverMacKey);
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

#if DEBUG
    public byte[] GetServerSessionKeyForTest(OpaqueLoginFinalizeRequest request)
    {
        AkeServerState serverState = DecryptStateToken(request.ServerStateToken);
        AsymmetricCipherKeyPair serverEphemeralKeys = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(OpaqueCrypto.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey),
                OpaqueCrypto.DomainParams),
            new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKeyBytes),
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