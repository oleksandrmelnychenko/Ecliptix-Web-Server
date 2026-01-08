using System.Security.Cryptography;
using Ecliptix.OPAQUE.Server;
using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using static Ecliptix.OPAQUE.Server.OpaqueServerNative;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Failures.Sodium;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolService : INativeOpaqueProtocolService, IDisposable
{
    private nint _server;
    private nint _currentServerState;
    private DerivedServerKeys? _serverKeys;

    public Result<Unit, OpaqueServerFailure> Initialize(string secretKeySeed)
    {
        try
        {
            Result<DerivedServerKeys, OpaqueServerFailure> keyResult = DeriveKeysFromMaterial(secretKeySeed);
            if (keyResult.IsErr)
            {
                return Result<Unit, OpaqueServerFailure>.Err(keyResult.UnwrapErr());
            }

            _serverKeys = keyResult.Unwrap();

            OpaqueResult result = (OpaqueResult)opaque_server_create_with_keys(
                _serverKeys.PrivateKey, (nuint)_serverKeys.PrivateKey.Length,
                _serverKeys.PublicKey, (nuint)_serverKeys.PublicKey.Length,
                out _server);

            if (result == OpaqueResult.Success)
            {
                return Result<Unit, OpaqueServerFailure>.Ok(Unit.Value);
            }

            Array.Clear(_serverKeys.PrivateKey, 0, _serverKeys.PrivateKey.Length);
            _serverKeys = null;
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed(
                    $"Failed to create server with derived keys: {result}"));
        }
        catch (DllNotFoundException ex)
        {
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed(
                    $"Native library 'libopaque_server' not found: {ex.Message}"));
        }
        catch (BadImageFormatException ex)
        {
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed(
                    $"Native library 'libopaque_server' failed to load: {ex.Message}"));
        }
        catch (EntryPointNotFoundException ex)
        {
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed(
                    $"Native library 'libopaque_server' entry point missing: {ex.Message}"));
        }
        catch (Exception ex)
        {
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.InitializationException(ex));
        }
    }

    public Result<RegistrationResponse, OpaqueServerFailure>
        CreateRegistrationResponse(RegistrationRequest request, Guid accountId)
    {
        byte[] responseBuffer = new byte[OpaqueConstants.REGISTRATION_RESPONSE_LENGTH];
        byte[] accountIdBytes = accountId.ToByteArray();

        OpaqueResult result = (OpaqueResult)opaque_server_create_registration_response(
            _server, request.Data, (nuint)request.Data.Length,
            accountIdBytes, (nuint)accountIdBytes.Length,
            responseBuffer, (nuint)responseBuffer.Length);

        if (result != OpaqueResult.Success)
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(
                OpaqueServerFailure.RegistrationFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToCreateRegistrationResponse}: {result}"));
        }

        Result<RegistrationResponse, OpaqueServerFailure> registrationResult =
            RegistrationResponse.Create(responseBuffer);
        if (registrationResult.IsErr)
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(registrationResult.UnwrapErr());
        }

        return Result<RegistrationResponse, OpaqueServerFailure>.Ok(registrationResult.Unwrap());
    }

    public Result<KE2, OpaqueServerFailure> GenerateKe2(KE1 ke1, Guid accountId, byte[] registrationRecord)
    {
        byte[] ke2Buffer = new byte[OpaqueConstants.KE2_LENGTH];
        byte[] accountIdBytes = accountId.ToByteArray();

        OpaqueResult result = (OpaqueResult)opaque_server_state_create(out _currentServerState);
        if (result != OpaqueResult.Success)
        {
            return Result<KE2, OpaqueServerFailure>.Err(
                OpaqueServerFailure.KeyExchangeFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToCreateServerState}: {result}"));
        }

        result = (OpaqueResult)opaque_server_generate_ke2(
            _server, ke1.Data, (nuint)ke1.Data.Length,
            accountIdBytes, (nuint)accountIdBytes.Length,
            registrationRecord, (nuint)registrationRecord.Length,
            ke2Buffer, (nuint)ke2Buffer.Length, _currentServerState);

        if (result != OpaqueResult.Success)
        {
            opaque_server_state_destroy(_currentServerState);
            _currentServerState = 0;
            return Result<KE2, OpaqueServerFailure>.Err(
                OpaqueServerFailure.KeyExchangeFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToGenerateKE2}: {result}"));
        }

        Result<KE2, OpaqueServerFailure> ke2Result = KE2.Create(ke2Buffer);
        return ke2Result.IsErr
            ? Result<KE2, OpaqueServerFailure>.Err(ke2Result.UnwrapErr())
            : Result<KE2, OpaqueServerFailure>.Ok(ke2Result.Unwrap());
    }

    public Result<SodiumSecureMemoryHandle, OpaqueServerFailure> FinishAuthentication(KE3 ke3)
    {
        Result<(SodiumSecureMemoryHandle SessionKey, SodiumSecureMemoryHandle MasterKey), OpaqueServerFailure> result =
            FinishAuthenticationWithMasterKey(ke3);

        if (result.IsErr)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(result.UnwrapErr());
        }

        (SodiumSecureMemoryHandle sessionKey, SodiumSecureMemoryHandle masterKey) = result.Unwrap();
        masterKey.Dispose();
        return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Ok(sessionKey);
    }

    public Result<(SodiumSecureMemoryHandle SessionKey, SodiumSecureMemoryHandle MasterKey), OpaqueServerFailure>
        FinishAuthenticationWithMasterKey(KE3 ke3)
    {
        byte[] sessionKeyBuffer = new byte[OpaqueConstants.HASH_LENGTH];
        byte[] masterKeyBuffer = new byte[OpaqueConstants.MASTER_KEY_LENGTH];

        try
        {
            OpaqueResult result = (OpaqueResult)opaque_server_finish(
                _server, ke3.Data, (nuint)ke3.Data.Length, _currentServerState,
                sessionKeyBuffer, (nuint)sessionKeyBuffer.Length,
                masterKeyBuffer, (nuint)masterKeyBuffer.Length);

            opaque_server_state_destroy(_currentServerState);
            _currentServerState = 0;

            if (result != OpaqueResult.Success)
            {
                return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Err(
                    OpaqueServerFailure.AuthenticationFailed(
                        $"{OpaqueServerConstants.ErrorMessages.FailedToFinishAuthentication}: {result}"));
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> sessionHandleResult =
                SodiumSecureMemoryHandle.Allocate(OpaqueConstants.HASH_LENGTH);

            if (sessionHandleResult.IsErr)
            {
                return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Err(
                    OpaqueServerFailure.MemoryAllocationFailed(sessionHandleResult.UnwrapErr().Message));
            }

            SodiumSecureMemoryHandle sessionHandle = sessionHandleResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = sessionHandle.Write(sessionKeyBuffer);
            if (writeResult.IsErr)
            {
                sessionHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Err(
                    OpaqueServerFailure.MemoryWriteFailed(writeResult.UnwrapErr().Message));
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> masterHandleResult =
                SodiumSecureMemoryHandle.Allocate(OpaqueConstants.MASTER_KEY_LENGTH);

            if (masterHandleResult.IsErr)
            {
                sessionHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Err(
                    OpaqueServerFailure.MemoryAllocationFailed(masterHandleResult.UnwrapErr().Message));
            }

            SodiumSecureMemoryHandle masterHandle = masterHandleResult.Unwrap();

            writeResult = masterHandle.Write(masterKeyBuffer);
            if (writeResult.IsErr)
            {
                sessionHandle.Dispose();
                masterHandle.Dispose();
                return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Err(
                    OpaqueServerFailure.MemoryWriteFailed(writeResult.UnwrapErr().Message));
            }

            return Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Ok(
                (sessionHandle, masterHandle));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKeyBuffer);
            CryptographicOperations.ZeroMemory(masterKeyBuffer);
        }
    }

    public Result<byte[], OpaqueServerFailure> GetServerPublicKey()
    {
        byte[] publicKeyCopy = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];
        Array.Copy(_serverKeys!.PublicKey, publicKeyCopy, OpaqueConstants.PUBLIC_KEY_LENGTH);

        return Result<byte[], OpaqueServerFailure>.Ok(publicKeyCopy);
    }

    public void Dispose()
    {
        if (_serverKeys != null)
        {
            Array.Clear(_serverKeys.PrivateKey, 0, _serverKeys.PrivateKey.Length);
            Array.Clear(_serverKeys.PublicKey, 0, _serverKeys.PublicKey.Length);
            _serverKeys = null;
        }

        if (_currentServerState != 0)
        {
            opaque_server_state_destroy(_currentServerState);
            _currentServerState = 0;
        }

        if (_server == 0)
        {
            return;
        }

        opaque_server_destroy(_server);
        _server = 0;
    }

    private static Result<DerivedServerKeys, OpaqueServerFailure> DeriveKeysFromMaterial(string keyMaterial)
    {
        byte[] keyMaterialBytes = Convert.FromHexString(keyMaterial);
        DerivedServerKeys keys = new()
        {
            PrivateKey = new byte[OpaqueConstants.PRIVATE_KEY_LENGTH],
            PublicKey = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH]
        };

        OpaqueResult result = (OpaqueResult)opaque_server_derive_keypair_from_seed(
            keyMaterialBytes, (nuint)keyMaterialBytes.Length,
            keys.PrivateKey, (nuint)keys.PrivateKey.Length,
            keys.PublicKey, (nuint)keys.PublicKey.Length);

        if (result != OpaqueResult.Success)
        {
            return Result<DerivedServerKeys, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed($"Failed to derive keys from seed: {result}"));
        }

        return Result<DerivedServerKeys, OpaqueServerFailure>.Ok(keys);
    }

    private sealed class DerivedServerKeys
    {
        public byte[] PrivateKey { get; set; } = new byte[OpaqueConstants.PRIVATE_KEY_LENGTH];
        public byte[] PublicKey { get; set; } = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];
    }
}
