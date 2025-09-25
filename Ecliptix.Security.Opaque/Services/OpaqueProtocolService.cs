using System.Text;
using Ecliptix.Security.Opaque.Models;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.Security.Opaque.Native;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Domain.Utilities;
using Serilog;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolService : INativeOpaqueProtocolService, IDisposable
{
    private nint _server;
    private nint _credentialStore;
    private nint _currentServerState;
    private volatile bool _isInitialized;
  
    public async Task<Result<Unit, OpaqueServerFailure>> InitializeAsync()
    {
        return await Task.Run(Initialize);
    }

    private Result<Unit, OpaqueServerFailure> Initialize()
    {
        try
        {
            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_server_keypair_generate(out nint serverKeyPair);
            if (result != OpaqueResult.Success)
                return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.LibraryInitializationFailed($"{OpaqueServerConstants.ErrorMessages.FailedToGenerateServerKeyPair}: {result}"));

            result = (OpaqueResult)OpaqueServerNative.opaque_server_create(serverKeyPair, out _server);
            if (result != OpaqueResult.Success)
            {
                OpaqueServerNative.opaque_server_keypair_destroy(serverKeyPair);
                return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.LibraryInitializationFailed($"{OpaqueServerConstants.ErrorMessages.FailedToCreateServer}: {result}"));
            }

            OpaqueServerNative.opaque_server_keypair_destroy(serverKeyPair);

            result = (OpaqueResult)OpaqueServerNative.opaque_credential_store_create(out _credentialStore);
            if (result != OpaqueResult.Success)
                return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.LibraryInitializationFailed($"{OpaqueServerConstants.ErrorMessages.FailedToCreateCredentialStore}: {result}"));

            _isInitialized = true;
            Log.Information("OPAQUE server service initialized successfully");

            return Result<Unit, OpaqueServerFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.InitializationException(ex));
        }
    }

    public async Task<Result<(RegistrationResponse Response, byte[] ServerCredentials), OpaqueServerFailure>> CreateRegistrationResponseAsync(RegistrationRequest request)
    {
        await Task.Yield();

        if (!_isInitialized)
            return Result<(RegistrationResponse, byte[]), OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceNotInitialized());

        try
        {
            if (request?.Data == null || request.Data.Length == 0)
                return Result<(RegistrationResponse, byte[]), OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.RegistrationRequestDataRequired));

            byte[] responseBuffer = new byte[OpaqueConstants.REGISTRATION_RESPONSE_LENGTH];
            byte[] credentialsBuffer = new byte[OpaqueConstants.ENVELOPE_LENGTH + OpaqueConstants.PRIVATE_KEY_LENGTH + OpaqueConstants.PUBLIC_KEY_LENGTH];

            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_server_create_registration_response(
                _server, request.Data, (nuint)request.Data.Length,
                responseBuffer, (nuint)responseBuffer.Length,
                credentialsBuffer, (nuint)credentialsBuffer.Length);

            if (result != OpaqueResult.Success)
                return Result<(RegistrationResponse, byte[]), OpaqueServerFailure>.Err(OpaqueServerFailure.RegistrationFailed($"{OpaqueServerConstants.ErrorMessages.FailedToCreateRegistrationResponse}: {result}"));

            Result<RegistrationResponse, OpaqueServerFailure> registrationResult = RegistrationResponse.Create(responseBuffer);
            if (registrationResult.IsErr)
                return Result<(RegistrationResponse, byte[]), OpaqueServerFailure>.Err(registrationResult.UnwrapErr());

            return Result<(RegistrationResponse, byte[]), OpaqueServerFailure>.Ok((registrationResult.Unwrap(), credentialsBuffer));
        }
        catch (Exception ex)
        {
            return Result<(RegistrationResponse, byte[]), OpaqueServerFailure>.Err(OpaqueServerFailure.CryptographicException(ex));
        }
    }

    public async Task<Result<KE2, OpaqueServerFailure>> GenerateKE2Async(KE1 ke1, byte[] storedCredentials)
    {
        await Task.Yield();

        if (!_isInitialized)
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceNotInitialized());

        try
        {
            if (ke1?.Data == null || ke1.Data.Length == 0)
                return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.KE1DataRequired));

            if (storedCredentials.Length == 0)
                return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.StoredCredentialsRequired));

            byte[] ke2Buffer = new byte[OpaqueConstants.KE2_LENGTH];

            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_server_state_create(out _currentServerState);
            if (result != OpaqueResult.Success)
                return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.KeyExchangeFailed($"{OpaqueServerConstants.ErrorMessages.FailedToCreateServerState}: {result}"));

            result = (OpaqueResult)OpaqueServerNative.opaque_server_generate_ke2(
                _server, ke1.Data, (nuint)ke1.Data.Length,
                storedCredentials, (nuint)storedCredentials.Length,
                ke2Buffer, (nuint)ke2Buffer.Length, _currentServerState);

            if (result != OpaqueResult.Success)
            {
                OpaqueServerNative.opaque_server_state_destroy(_currentServerState);
                _currentServerState = 0;
                return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.KeyExchangeFailed($"{OpaqueServerConstants.ErrorMessages.FailedToGenerateKE2}: {result}"));
            }

            Result<KE2, OpaqueServerFailure> ke2Result = KE2.Create(ke2Buffer);
            if (ke2Result.IsErr)
                return Result<KE2, OpaqueServerFailure>.Err(ke2Result.UnwrapErr());

            return Result<KE2, OpaqueServerFailure>.Ok(ke2Result.Unwrap());
        }
        catch (Exception ex)
        {
            if (_currentServerState != 0)
            {
                OpaqueServerNative.opaque_server_state_destroy(_currentServerState);
                _currentServerState = 0;
            }
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.CryptographicException(ex));
        }
    }

    public async Task<Result<SessionKey, OpaqueServerFailure>> FinishAuthenticationAsync(KE3 ke3)
    {
        await Task.Yield();

        if (!_isInitialized)
            return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceNotInitialized());

        try
        {
            if (_currentServerState == 0)
                return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.NoActiveServerState));

            if (ke3?.Data == null || ke3.Data.Length == 0)
                return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.KE3DataRequired));

            byte[] sessionKeyBuffer = new byte[OpaqueConstants.HASH_LENGTH];

            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_server_finish(
                _server, ke3.Data, (nuint)ke3.Data.Length, _currentServerState,
                sessionKeyBuffer, (nuint)sessionKeyBuffer.Length);

            OpaqueServerNative.opaque_server_state_destroy(_currentServerState);
            _currentServerState = 0;

            if (result != OpaqueResult.Success)
                return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.AuthenticationFailed($"{OpaqueServerConstants.ErrorMessages.FailedToFinishAuthentication}: {result}"));

            Result<SessionKey, OpaqueServerFailure> sessionKeyResult = SessionKey.Create(sessionKeyBuffer);
            if (sessionKeyResult.IsErr)
                return Result<SessionKey, OpaqueServerFailure>.Err(sessionKeyResult.UnwrapErr());

            return Result<SessionKey, OpaqueServerFailure>.Ok(sessionKeyResult.Unwrap());
        }
        catch (Exception ex)
        {
            if (_currentServerState != 0)
            {
                OpaqueServerNative.opaque_server_state_destroy(_currentServerState);
                _currentServerState = 0;
            }
            return Result<SessionKey, OpaqueServerFailure>.Err(OpaqueServerFailure.CryptographicException(ex));
        }
    }

    public async Task<Result<Unit, OpaqueServerFailure>> StoreUserCredentialsAsync(string userId, byte[] credentials)
    {
        await Task.Yield();

        if (!_isInitialized)
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceNotInitialized());

        try
        {
            if (string.IsNullOrEmpty(userId))
                return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.UserIdRequired));

            if (credentials.Length == 0)
                return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.CredentialsRequired));

            byte[] userIdBytes = Encoding.UTF8.GetBytes(userId);
            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_credential_store_store(
                _credentialStore, userIdBytes, (nuint)userIdBytes.Length,
                credentials, (nuint)credentials.Length);

            if (result != OpaqueResult.Success)
                return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.CredentialStorageFailed($"{OpaqueServerConstants.ErrorMessages.FailedToStoreCredentials} {userId}: {result}"));

            return Result<Unit, OpaqueServerFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.StorageException(ex));
        }
    }

    public async Task<Result<byte[], OpaqueServerFailure>> RetrieveUserCredentialsAsync(string userId)
    {
        await Task.Yield();

        if (!_isInitialized)
            return Result<byte[], OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceNotInitialized());

        try
        {
            if (string.IsNullOrEmpty(userId))
                return Result<byte[], OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.UserIdRequired));

            byte[] userIdBytes = Encoding.UTF8.GetBytes(userId);
            byte[] credentialsBuffer = new byte[OpaqueConstants.ENVELOPE_LENGTH + OpaqueConstants.PRIVATE_KEY_LENGTH + OpaqueConstants.PUBLIC_KEY_LENGTH];

            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_credential_store_retrieve(
                _credentialStore, userIdBytes, (nuint)userIdBytes.Length,
                credentialsBuffer, (nuint)credentialsBuffer.Length);

            if (result != OpaqueResult.Success)
                return Result<byte[], OpaqueServerFailure>.Err(OpaqueServerFailure.CredentialRetrievalFailed($"{OpaqueServerConstants.ErrorMessages.FailedToRetrieveCredentials} {userId}: {result}"));

            return Result<byte[], OpaqueServerFailure>.Ok(credentialsBuffer);
        }
        catch (Exception ex)
        {
            return Result<byte[], OpaqueServerFailure>.Err(OpaqueServerFailure.StorageException(ex));
        }
    }

    public void Dispose()
    {
        if (_currentServerState != 0)
        {
            OpaqueServerNative.opaque_server_state_destroy(_currentServerState);
            _currentServerState = 0;
        }

        if (_credentialStore != 0)
        {
            OpaqueServerNative.opaque_credential_store_destroy(_credentialStore);
            _credentialStore = 0;
        }

        if (_server != 0)
        {
            OpaqueServerNative.opaque_server_destroy(_server);
            _server = 0;
        }

        Log.Information(OpaqueServerConstants.LogMessages.ServerDisposed);
    }
}