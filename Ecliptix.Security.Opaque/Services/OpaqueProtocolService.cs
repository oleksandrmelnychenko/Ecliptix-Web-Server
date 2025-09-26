using System.Text;
using System.Security.Cryptography;
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
    private nint _currentServerState;
    private volatile bool _isInitialized;
    private string? _secretKeySeed;
    private DerivedServerKeys? _serverKeys;

    private class DerivedServerKeys
    {
        public byte[] PrivateKey { get; set; } = new byte[OpaqueConstants.PRIVATE_KEY_LENGTH];
        public byte[] PublicKey { get; set; } = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];
    }
  
    public async Task<Result<Unit, OpaqueServerFailure>> InitializeAsync(string? secretKeySeed = null)
    {
        return await Task.Run(() => Initialize(secretKeySeed));
    }

    private Result<Unit, OpaqueServerFailure> Initialize(string? secretKeySeed = null)
    {
        try
        {
            _secretKeySeed = secretKeySeed;
            OpaqueResult result;

            if (!string.IsNullOrEmpty(secretKeySeed))
            {
                Log.Information("OPAQUE server initializing with deterministic keys from seed");

                Result<DerivedServerKeys, OpaqueServerFailure> keyResult = DeriveKeysFromSeed(secretKeySeed);
                if (keyResult.IsErr)
                    return Result<Unit, OpaqueServerFailure>.Err(keyResult.UnwrapErr());

                _serverKeys = keyResult.Unwrap();

                result = (OpaqueResult)OpaqueServerNative.opaque_server_create_with_keys(
                    _serverKeys.PrivateKey, (nuint)_serverKeys.PrivateKey.Length,
                    _serverKeys.PublicKey, (nuint)_serverKeys.PublicKey.Length,
                    out _server);

                if (result != OpaqueResult.Success)
                {
                    Array.Clear(_serverKeys.PrivateKey, 0, _serverKeys.PrivateKey.Length);
                    _serverKeys = null;
                    return Result<Unit, OpaqueServerFailure>.Err(
                        OpaqueServerFailure.LibraryInitializationFailed($"Failed to create server with derived keys: {result}"));
                }

                Log.Information("OPAQUE server initialized with static keys for consistent server identity");
            }
            else
            {
                Log.Information("OPAQUE server initializing with default hardcoded keys");
                result = (OpaqueResult)OpaqueServerNative.opaque_server_create_default(out _server);

                if (result != OpaqueResult.Success)
                    return Result<Unit, OpaqueServerFailure>.Err(
                        OpaqueServerFailure.LibraryInitializationFailed($"{OpaqueServerConstants.ErrorMessages.FailedToCreateServer}: {result}"));
            }


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


    public void Dispose()
    {
        if (_serverKeys != null)
        {
            Array.Clear(_serverKeys.PrivateKey, 0, _serverKeys.PrivateKey.Length);
            Array.Clear(_serverKeys.PublicKey, 0, _serverKeys.PublicKey.Length);
            _serverKeys = null;
            Log.Information("OPAQUE server keys cleared from memory");
        }

        if (_currentServerState != 0)
        {
            OpaqueServerNative.opaque_server_state_destroy(_currentServerState);
            _currentServerState = 0;
        }


        if (_server != 0)
        {
            OpaqueServerNative.opaque_server_destroy(_server);
            _server = 0;
        }

        Log.Information(OpaqueServerConstants.LogMessages.ServerDisposed);
    }

    public Result<byte[], OpaqueServerFailure> GetServerPublicKey()
    {
        if (!_isInitialized)
            return Result<byte[], OpaqueServerFailure>.Err(
                OpaqueServerFailure.ServiceNotInitialized());

        if (_serverKeys == null)
            return Result<byte[], OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput("Server keys not available - using default hardcoded keys"));

        byte[] publicKeyCopy = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];
        Array.Copy(_serverKeys.PublicKey, publicKeyCopy, OpaqueConstants.PUBLIC_KEY_LENGTH);

        return Result<byte[], OpaqueServerFailure>.Ok(publicKeyCopy);
    }

    private Result<DerivedServerKeys, OpaqueServerFailure> DeriveKeysFromSeed(string seed)
    {
        try
        {
            byte[] seedBytes = Encoding.UTF8.GetBytes(seed);
            DerivedServerKeys keys = new DerivedServerKeys();

            OpaqueResult result = (OpaqueResult)OpaqueServerNative.opaque_server_derive_keypair_from_seed(
                seedBytes, (nuint)seedBytes.Length,
                keys.PrivateKey, (nuint)keys.PrivateKey.Length,
                keys.PublicKey, (nuint)keys.PublicKey.Length);

            if (result != OpaqueResult.Success)
                return Result<DerivedServerKeys, OpaqueServerFailure>.Err(
                    OpaqueServerFailure.LibraryInitializationFailed($"Failed to derive keys from seed: {result}"));

            byte[] publicKeyHash = SHA256.HashData(keys.PublicKey);
            Log.Information("OPAQUE server public key hash: {PublicKeyHash}",
                Convert.ToHexString(publicKeyHash[..8]));

            return Result<DerivedServerKeys, OpaqueServerFailure>.Ok(keys);
        }
        catch (Exception ex)
        {
            return Result<DerivedServerKeys, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InitializationException(ex));
        }
    }

}