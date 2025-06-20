using System.Collections.Concurrent;
using Ecliptix.Core.AuthenticationSystem;
using Ecliptix.Core.OpaqueProtocol;
using Ecliptix.Domain.Utilities;
using Org.BouncyCastle.Math;

namespace ProtocolTests;

[TestClass]
public class EcliptixPasswordAuthSystemTests
{
    [TestMethod]
    public async Task Full_Registration_And_Login_Flow_Should_Succeed()
    {
        string username = "testuser";
        string password = "a_Very!Complex-password123";
        byte[] serverSecretSeed = new byte[32];
        new Random().NextBytes(serverSecretSeed);
        ServerPasswordAuthSystem serverAuthSystem = new(serverSecretSeed);
        ConcurrentDictionary<string, UserOpaqueRecord> users = new();
        ClientPasswordAuthSystem clientAuthSystem = new(serverAuthSystem.PublicKey);

        (byte[] oprfRequest, BigInteger clientBlind) = clientAuthSystem.CreateOprfRequest(password);
        byte[] oprfResponse = serverAuthSystem.ProcessOprfRequest(oprfRequest);
        byte[] registrationRecord = clientAuthSystem.CreateRegistrationRecord(password, oprfResponse, clientBlind);
        UserOpaqueRecord userRecord = new(username, registrationRecord);
        users[username] = userRecord;

        Assert.IsTrue(users.TryGetValue(username, out var storedUser), "User record was not stored correctly.");
        Assert.IsNotNull(storedUser, "Stored user is null.");
        CollectionAssert.AreEqual(userRecord.RegistrationRecord, storedUser.RegistrationRecord,
            "Stored registration record does not match created record.");

        (byte[] loginOprfRequest, BigInteger loginClientBlind) = clientAuthSystem.CreateOprfRequest(password);
        Result<OpaqueLoginInitResponse, string> serverLoginResponseResult = await serverAuthSystem.CreateLoginResponseAsync(username, loginOprfRequest,
            async u => users.TryGetValue(u, out var user) ? user : null);
        Assert.IsTrue(serverLoginResponseResult.IsOk, serverLoginResponseResult.IsErr ? serverLoginResponseResult.UnwrapErr() : "Server failed to create a login response.");
        OpaqueLoginInitResponse serverLoginResponse = serverLoginResponseResult.Unwrap();

        (OpaqueLoginFinalizeRequest clientFinalizeRequest, byte[] clientSessionKey) = await clientAuthSystem.FinalizeLoginAsync(
            username,
            password,
            serverLoginResponse,
            loginClientBlind,
            async req => await Task.FromResult(serverAuthSystem.VerifyLoginFinalization(req)));

        Result<OpaqueLoginFinalizeResponse, string> serverVerificationResult = serverAuthSystem.VerifyLoginFinalization(clientFinalizeRequest);
        Assert.IsTrue(serverVerificationResult.IsOk, serverVerificationResult.IsErr ? serverVerificationResult.UnwrapErr() : "Server verification failed.");
        OpaqueLoginFinalizeResponse? serverFinalizeResponse = serverVerificationResult.Unwrap();
        Assert.IsNotNull(serverFinalizeResponse?.ServerMac, "Server's confirmation MAC should not be null.");

        Console.WriteLine("✅ Test Passed: Registration and login flow succeeded.");
    }

    [TestMethod]
    public async Task PasswordChange_Flow_Should_Succeed()
    {
        string username = "testuser";
        string oldPassword = "oldPassword123";
        string newPassword = "newPassword456";
        byte[] serverSecretSeed = new byte[32];
        new Random().NextBytes(serverSecretSeed);
        ServerPasswordAuthSystem serverAuthSystem = new(serverSecretSeed);
        ConcurrentDictionary<string, UserOpaqueRecord> users = new();
        ClientPasswordAuthSystem clientAuthSystem = new(serverAuthSystem.PublicKey);

        (byte[] oprfRequest, BigInteger blind) = clientAuthSystem.CreateOprfRequest(oldPassword);
        byte[] oprfResponse = serverAuthSystem.ProcessOprfRequest(oprfRequest);
        byte[] registrationRecord = clientAuthSystem.CreateRegistrationRecord(oldPassword, oprfResponse, blind);
        UserOpaqueRecord userRecord = new(username, registrationRecord);
        users[username] = userRecord;

        (byte[] newOprfRequest, BigInteger newBlind) = clientAuthSystem.CreateOprfRequest(newPassword);
        byte[] newOprfResponse = serverAuthSystem.ProcessOprfRequest(newOprfRequest);
        OpaquePasswordChangeRequest changeRequest = await clientAuthSystem.ChangePasswordAsync(
            username,
            oldPassword,
            newPassword,
            newOprfResponse,
            newBlind,
            async req => await Task.FromResult((await serverAuthSystem.CreateLoginResponseAsync(req.Username, req.OprfRequest,
                async u => users.TryGetValue(u, out var user) ? user : null)).Unwrap()),
            async req => await Task.FromResult(serverAuthSystem.VerifyLoginFinalization(req)));

        Result<bool, string> changeResult = await serverAuthSystem.ChangePasswordAsync(changeRequest,
            async (u, r) => users[u] = r);
        Assert.IsTrue(changeResult.IsOk, changeResult.IsErr ? changeResult.UnwrapErr() : "Password change failed.");

        Assert.IsTrue(users.TryGetValue(username, out var storedUser), "User not found after password change.");
        Assert.IsNotNull(storedUser);
        (byte[] loginOprfRequest, BigInteger loginBlind) = clientAuthSystem.CreateOprfRequest(newPassword);
        OpaqueLoginInitResponse loginInitResponse = (await serverAuthSystem.CreateLoginResponseAsync(username, loginOprfRequest,
            async u => users.TryGetValue(u, out var user) ? user : null)).Unwrap();
        (OpaqueLoginFinalizeRequest loginFinalizeRequest, _) = await clientAuthSystem.FinalizeLoginAsync(
            username,
            newPassword,
            loginInitResponse,
            loginBlind,
            async req => await Task.FromResult(serverAuthSystem.VerifyLoginFinalization(req)));
        Result<OpaqueLoginFinalizeResponse, string> loginResult = serverAuthSystem.VerifyLoginFinalization(loginFinalizeRequest);
        Assert.IsTrue(loginResult.IsOk, loginResult.IsErr ? loginResult.UnwrapErr() : "Login with new password failed.");
        Console.WriteLine("✅ Test Passed: Password change flow succeeded.");
    }
}