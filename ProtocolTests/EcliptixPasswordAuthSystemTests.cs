using System.Collections.Concurrent;
using Ecliptix.Core.AuthenticationSystem;
using Org.BouncyCastle.Crypto;

namespace ProtocolTests;

[TestClass]
public class EcliptixPasswordAuthSystemTests
{
    [TestMethod]
    public void Full_Registration_And_Login_Flow_Should_Succeed_And_Derive_Matching_Session_Keys()
    {
        // 1. Define test user credentials
        string username = "testuser";
        string password = "a_Very!Complex-password123";

        // 2. Create the server-side system and a mock database
        byte[] serverSecretSeed = new byte[32];
        new Random().NextBytes(serverSecretSeed);
        var serverAuthSystem = new ServerPasswordAuthSystem(serverSecretSeed);
        var mockRepo = new MockUserRepository();

        // 3. Get the server's static public key
        AsymmetricKeyParameter? serverStaticPublicKey = serverAuthSystem.ServerStaticKeyPair.Public;

        // 4. Create the client-side system with the server's public key
        ClientPasswordAuthSystem clientAuthSystem = new(serverStaticPublicKey);
        // ACT (REGISTRATION) ======================================================

        // --- Client Side: Step 1 (Create OPRF Request) ---
        var (oprfRequest, clientBlind) = clientAuthSystem.CreateOprfRequest(password);

        // --- Server Side: Step 1 (Process OPRF Request) ---
        var oprfResponse = serverAuthSystem.ProcessOprfRequest(oprfRequest);

        // --- Client Side: Step 2 (Create Final Registration Record) ---
        var registrationRecord = clientAuthSystem.CreateRegistrationRecord(password, oprfResponse, clientBlind);

        // --- Server Side: Step 2 (Store the Record) ---
        var userRecord = new UserOpaqueRecord(username, registrationRecord);
        mockRepo.StoreUserAsync(userRecord).Wait();

        // ASSERT (REGISTRATION)
        var storedUser = mockRepo.GetUserByUsernameAsync(username).Result;
        Assert.IsNotNull(storedUser, "User record was not stored correctly.");
        CollectionAssert.AreEqual(userRecord.RegistrationRecord, storedUser.RegistrationRecord,
            "Stored registration record does not match created record.");

        // ACT (LOGIN) =============================================================

        // --- Client Side: Step 1 (Start Login) ---
        var (loginOprfRequest, loginClientBlind) = clientAuthSystem.CreateOprfRequest(password);

        // --- Server Side: Step 1 (Create Login Response) ---
        var serverLoginResponseResult =
            serverAuthSystem.CreateLoginResponse(username, loginOprfRequest, storedUser);
        Assert.IsTrue(serverLoginResponseResult.IsOk, "Server failed to create a login response.");
        var serverLoginResponse = serverLoginResponseResult.Unwrap();

        // --- Client Side: Step 2 (Finalize Login & Derive Client Session Key) ---
        var (clientFinalizeRequest, clientSessionKey) =
            clientAuthSystem.FinalizeLogin(username, password, serverLoginResponse, loginClientBlind);

        // --- Server Side: Step 2 (Verify Client's Final Request) ---
        var serverVerificationResult = serverAuthSystem.VerifyLoginFinalization(clientFinalizeRequest);

        // ASSERT (LOGIN) ==========================================================

        // 1. Check that the server successfully verified the client
        if (!serverVerificationResult.IsOk)
        {
            Assert.Fail($"Server verification failed with: {serverVerificationResult.UnwrapErr()}");
        }

        Assert.IsTrue(serverVerificationResult.IsOk);
        var serverFinalizeResponse = serverVerificationResult.Unwrap();
        Assert.IsNotNull(serverFinalizeResponse?.ServerMac, "Server's confirmation MAC should not be null.");

        // 2. Get the server's session key for comparison
        var serverSessionKey = serverAuthSystem.GetServerSessionKeyForTest(clientFinalizeRequest);

        // 3. Confirm that the client and server derived the same session key
        CollectionAssert.AreEqual(clientSessionKey, serverSessionKey,
            "CRITICAL FAILURE: DERIVED SESSION KEYS DO NOT MATCH!");

        Console.WriteLine("✅ Test Passed: Client and Server successfully derived the same session key.");
    }

    [TestMethod]
    public async Task PasswordChange_Flow_Should_Succeed()
    {
        // Arrange
        string username = "testuser";
        string oldPassword = "oldPassword123";
        string newPassword = "newPassword456";
        byte[] serverSecretSeed = new byte[32];
        new Random().NextBytes(serverSecretSeed);
        var serverAuthSystem = new ServerPasswordAuthSystem(serverSecretSeed);
        var mockRepo = new MockUserRepository();
        var clientAuthSystem = new ClientPasswordAuthSystem(serverAuthSystem.ServerStaticKeyPair.Public);

        // Register user
        var (oprfRequest, blind) = clientAuthSystem.CreateOprfRequest(oldPassword);
        var oprfResponse = serverAuthSystem.ProcessOprfRequest(oprfRequest);
        var registrationRecord = clientAuthSystem.CreateRegistrationRecord(oldPassword, oprfResponse, blind);
        var userRecord = new UserOpaqueRecord(username, registrationRecord);
        await mockRepo.StoreUserAsync(userRecord);

        // Mock server API calls
        clientAuthSystem.SetServerMock(serverAuthSystem, mockRepo);

        // Act: Change password
        var (newOprfRequest, newBlind) = clientAuthSystem.CreateOprfRequest(newPassword);
        var newOprfResponse = serverAuthSystem.ProcessOprfRequest(newOprfRequest);
        var changeRequest =
            await clientAuthSystem.ChangePasswordAsync(username, oldPassword, newPassword, newOprfResponse, newBlind);
        var changeResult = serverAuthSystem.ChangePassword(changeRequest, (u, r) => mockRepo.StoreUserAsync(r));
        Assert.IsTrue(changeResult.IsOk, "Password change failed.");

        // Assert: Verify login with new password
        var storedUser = await mockRepo.GetUserByUsernameAsync(username);
        var (loginOprfRequest, loginBlind) = clientAuthSystem.CreateOprfRequest(newPassword);
        var loginInitResponse = serverAuthSystem.CreateLoginResponse(username, loginOprfRequest, storedUser).Unwrap();
        var (loginFinalizeRequest, _) =
            clientAuthSystem.FinalizeLogin(username, newPassword, loginInitResponse, loginBlind);
        var loginResult = serverAuthSystem.VerifyLoginFinalization(loginFinalizeRequest);
        Assert.IsTrue(loginResult.IsOk, "Login with new password failed.");
    }
}