using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ecliptix.Core.OpaqueProtocol;
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

public record OpaquePasswordResetInitRequest(string Username);

public record OpaquePasswordResetInitResponse(bool Success, string Message);

public record OpaquePasswordResetFinalizeRequest(string Username, string ResetToken, byte[] NewRegistrationRecord);

public record OpaquePasswordChangeRequest(
    string Username,
    byte[] ServerStateToken,
    byte[] NewRegistrationRecord,
    byte[] ClientEphemeralPublicKey);

public class ServerPasswordAuthSystem
{
    private readonly BigInteger _serverOprfKey;
    private readonly byte[] _serverTokenEncryptionKey;
    private readonly AsymmetricCipherKeyPair _serverStaticKeyPair;

    public AsymmetricKeyParameter PublicKey
    {
        get { return _serverStaticKeyPair.Public; }
    }

    public ServerPasswordAuthSystem(byte[] serverSecretSeed)
    {
        if (serverSecretSeed == null || serverSecretSeed.Length < 32)
            throw new ArgumentException("Server secret seed must be at least 32 bytes.");
        _serverOprfKey = new BigInteger(1,
            OpaqueCryptoUtilities.DeriveKey(serverSecretSeed, null, Encoding.UTF8.GetBytes("oprf_key"), 32));
        _serverTokenEncryptionKey =
            OpaqueCryptoUtilities.DeriveKey(serverSecretSeed, null, Encoding.UTF8.GetBytes("token_key"), 32);
        _serverStaticKeyPair = OpaqueCryptoUtilities.GenerateKeyPair();
    }

    public byte[] ProcessOprfRequest(byte[] oprfRequest)
    {
        ECPoint requestPoint = OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(oprfRequest);
        ECPoint responsePoint = requestPoint.Multiply(_serverOprfKey);
        return responsePoint.GetEncoded(true);
    }

    public async Task<Result<OpaqueLoginInitResponse, string>> CreateLoginResponseAsync(
        string username,
        byte[] oprfRequest,
        Func<string, Task<UserOpaqueRecord>> getUserRecord)
    {
        try
        {
            var userRecord = await getUserRecord(username);
            if (userRecord == null)
                return Result<OpaqueLoginInitResponse, string>.Err("User not found.");

            byte[] oprfResponse = ProcessOprfRequest(oprfRequest);
            AsymmetricCipherKeyPair serverEphemeralKeys = OpaqueCryptoUtilities.GenerateKeyPair();
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

            Result<byte[], OpaqueFailure> encryptedStateToken = OpaqueCryptoUtilities.Encrypt(
                JsonSerializer.SerializeToUtf8Bytes(serverState),
                _serverTokenEncryptionKey, null);

            return Result<OpaqueLoginInitResponse, string>.Ok(new OpaqueLoginInitResponse(oprfResponse,
                serverEphemeralPublicKeyBytes, userRecord.RegistrationRecord, encryptedStateToken.Unwrap()));
        }
        catch (Exception ex)
        {
            return Result<OpaqueLoginInitResponse, string>.Err($"Failed to create login response: {ex.Message}");
        }
    }

    public Result<OpaqueLoginFinalizeResponse, string> VerifyLoginFinalization(OpaqueLoginFinalizeRequest request)
    {
        try
        {
            var serverState = DecryptStateToken(request.ServerStateToken);
            if (serverState.Expiration < DateTimeOffset.UtcNow)
                return Result<OpaqueLoginFinalizeResponse, string>.Err("Invalid or expired server state token.");

            AsymmetricCipherKeyPair serverEphemeralKeys = new AsymmetricCipherKeyPair(
                new ECPublicKeyParameters(
                    OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ServerEphemeralPublicKey),
                    OpaqueCryptoUtilities.DomainParams),
                new ECPrivateKeyParameters(new BigInteger(1, serverState.ServerEphemeralPrivateKeyBytes),
                    OpaqueCryptoUtilities.DomainParams));

            ECPoint clientStaticPublicKey =
                OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(serverState.ClientStaticPublicKey);
            ECPoint clientEphemeralPublicKey =
                OpaqueCryptoUtilities.DomainParams.Curve.DecodePoint(request.ClientEphemeralPublicKey);

            byte[] akeResult = PerformServerAke(serverEphemeralKeys,
                (ECPrivateKeyParameters)_serverStaticKeyPair.Private, clientStaticPublicKey, clientEphemeralPublicKey);
            byte[] serverStaticPublicKeyBytes = ((ECPublicKeyParameters)_serverStaticKeyPair.Public).Q.GetEncoded(true);

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
        catch (Exception ex)
        {
            return Result<OpaqueLoginFinalizeResponse, string>.Err($"Failed to verify login: {ex.Message}");
        }
    }

    public async Task<Result<OpaquePasswordResetInitResponse, string>> InitiatePasswordResetAsync(
        OpaquePasswordResetInitRequest request,
        Func<string, Task<bool>> userExists,
        Func<string, string, Task> sendResetToken)
    {
        try
        {
            if (!await userExists(request.Username))
                return Result<OpaquePasswordResetInitResponse, string>.Err("User not found.");

            string resetToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var resetState = new AkePasswordResetState
            {
                Username = request.Username,
                ResetToken = resetToken,
                Expiration = DateTimeOffset.UtcNow.AddHours(1)
            };

            // Store reset state (requires external storage callback)
            await StoreResetStateAsync(resetState);

            // Send reset token (e.g., via email)
            await sendResetToken(request.Username, resetToken);

            return Result<OpaquePasswordResetInitResponse, string>.Ok(
                new OpaquePasswordResetInitResponse(true, $"Password reset initiated for {request.Username}."));
        }
        catch (Exception ex)
        {
            return Result<OpaquePasswordResetInitResponse, string>.Err(
                $"Failed to initiate password reset: {ex.Message}");
        }
    }

    public async Task<Result<bool, string>> FinalizePasswordResetAsync(
        OpaquePasswordResetFinalizeRequest request,
        Func<string, Task<AkePasswordResetState>> getResetState,
        Func<string, Task> removeResetState,
        Func<string, UserOpaqueRecord, Task> updateUserRecord)
    {
        try
        {
            var resetState = await getResetState(request.Username);
            if (resetState == null)
                return Result<bool, string>.Err("No password reset request found for user.");

            if (resetState.Expiration < DateTimeOffset.UtcNow)
                return Result<bool, string>.Err("Password reset token has expired.");

            if (resetState.ResetToken != request.ResetToken)
                return Result<bool, string>.Err("Invalid password reset token.");

            // Update user record with new registration record
            var newUserRecord = new UserOpaqueRecord(request.Username, request.NewRegistrationRecord);
            await updateUserRecord(request.Username, newUserRecord);

            // Remove reset state
            await removeResetState(request.Username);

            return Result<bool, string>.Ok(true);
        }
        catch (Exception ex)
        {
            return Result<bool, string>.Err($"Failed to finalize password reset: {ex.Message}");
        }
    }

    public async Task<Result<bool, string>> ChangePasswordAsync(
        OpaquePasswordChangeRequest request,
        Func<string, UserOpaqueRecord, Task> updateUserRecord)
    {
        try
        {
            // Decrypt the server state token to verify authentication context
            var serverState = DecryptStateToken(request.ServerStateToken);
            if (serverState.Expiration < DateTimeOffset.UtcNow)
                return Result<bool, string>.Err("Invalid or expired server state token.");

            // Update user record with new registration record
            var newUserRecord = new UserOpaqueRecord(request.Username, request.NewRegistrationRecord);
            await updateUserRecord(request.Username, newUserRecord);

            return Result<bool, string>.Ok(true);
        }
        catch (Exception ex)
        {
            return Result<bool, string>.Err($"Failed to change password: {ex.Message}");
        }
    }

    private async Task StoreResetStateAsync(AkePasswordResetState resetState)
    {
        // In-memory storage for simplicity; replace with database in production
        _passwordResetStates[resetState.Username] = resetState;
        // In a real app, use a database or cache
        await Task.CompletedTask;
    }

    private Dictionary<string, AkePasswordResetState> _passwordResetStates = new();

    private AkeServerState DecryptStateToken(byte[] serverStateToken)
    {
        Result<byte[], OpaqueFailure> decryptedState = OpaqueCryptoUtilities.Decrypt(serverStateToken, _serverTokenEncryptionKey, null);
        return JsonSerializer.Deserialize<AkeServerState>(decryptedState.Unwrap());
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
        var prkResult = OpaqueCryptoUtilities.HkdfExtract(akeResult, salt);
        var prk = prkResult.Unwrap();
        byte[] sessionKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("session_key").Concat(transcriptHash).ToArray(), 32);
        byte[] clientMacKey = OpaqueCryptoUtilities.HkdfExpand(prk,
            Encoding.UTF8.GetBytes("client_mac_key").Concat(transcriptHash).ToArray(), 32);
        byte[] serverMacKey = OpaqueCryptoUtilities.HkdfExpand(prk,
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
}