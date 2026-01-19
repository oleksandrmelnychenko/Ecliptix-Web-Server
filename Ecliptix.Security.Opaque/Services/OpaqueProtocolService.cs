using System.Security.Cryptography;
using Ecliptix.OPAQUE.Relay;
using Ecliptix.Security.Opaque.Constants;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Failures.Sodium;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueProtocolService : IDisposable
{
    private OpaqueServer? _server;
    private AuthenticationState? _currentServerState;
    private ServerKeyPair? _serverKeys;
    private bool _disposed;

    public Result<Unit, OpaqueServerFailure> Initialize(string secretKeySeed)
    {
        if (_disposed)
        {
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceDisposed());
        }

        ResetServer();

        Result<ServerKeyPair, OpaqueServerFailure> keyResult = DeriveKeysFromMaterial(secretKeySeed);
        if (keyResult.IsErr)
        {
            return Result<Unit, OpaqueServerFailure>.Err(keyResult.UnwrapErr());
        }

        _serverKeys = keyResult.Unwrap();

        try
        {
            _server = OpaqueServer.Create(_serverKeys);
            return Result<Unit, OpaqueServerFailure>.Ok(Unit.Value);
        }
        catch (OpaqueException ex)
        {
            ResetServer();
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToCreateServer}: {ex.ResultCode}"));
        }
        catch (ArgumentException ex)
        {
            ResetServer();
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(ex.Message));
        }
        catch (Exception ex)
        {
            ResetServer();
            return Result<Unit, OpaqueServerFailure>.Err(OpaqueServerFailure.InitializationException(ex));
        }
    }

    public Result<RegistrationResponse, OpaqueServerFailure>
        CreateRegistrationResponse(RegistrationRequest request, Guid accountId)
    {
        if (!TryEnsureReady(out OpaqueServerFailure failure))
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(failure);
        }

        byte[] accountIdBytes = accountId.ToByteArray();

        try
        {
            byte[] responseBuffer = _server!.CreateRegistrationResponse(request.Data, accountIdBytes);
            Result<RegistrationResponse, OpaqueServerFailure> registrationResult =
                RegistrationResponse.Create(responseBuffer);

            return registrationResult.IsErr
                ? Result<RegistrationResponse, OpaqueServerFailure>.Err(registrationResult.UnwrapErr())
                : Result<RegistrationResponse, OpaqueServerFailure>.Ok(registrationResult.Unwrap());
        }
        catch (ArgumentException ex)
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(
                OpaqueServerFailure.RegistrationFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToCreateRegistrationResponse}: {ex.ResultCode}"));
        }
        catch (ObjectDisposedException)
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceDisposed());
        }
        catch (Exception ex)
        {
            return Result<RegistrationResponse, OpaqueServerFailure>.Err(OpaqueServerFailure.CryptographicException(ex));
        }
    }

    public Result<KE2, OpaqueServerFailure> GenerateKe2(KE1 ke1, Guid accountId, byte[] registrationRecord)
    {
        if (!TryEnsureReady(out OpaqueServerFailure failure))
        {
            return Result<KE2, OpaqueServerFailure>.Err(failure);
        }

        ResetServerState();

        byte[] accountIdBytes = accountId.ToByteArray();
        AuthenticationState authState;
        try
        {
            authState = AuthenticationState.Create();
        }
        catch (OpaqueException ex)
        {
            return Result<KE2, OpaqueServerFailure>.Err(
                OpaqueServerFailure.KeyExchangeFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToCreateServerState}: {ex.ResultCode}"));
        }
        catch (Exception ex)
        {
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.CryptographicException(ex));
        }

        try
        {
            byte[] ke2Buffer = _server!.GenerateKe2(
                ke1.Data,
                accountIdBytes,
                registrationRecord,
                authState);

            Result<KE2, OpaqueServerFailure> ke2Result = KE2.Create(ke2Buffer);
            if (ke2Result.IsErr)
            {
                authState.Dispose();
                return Result<KE2, OpaqueServerFailure>.Err(ke2Result.UnwrapErr());
            }

            _currentServerState = authState;
            return Result<KE2, OpaqueServerFailure>.Ok(ke2Result.Unwrap());
        }
        catch (ArgumentException ex)
        {
            authState.Dispose();
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            authState.Dispose();
            return Result<KE2, OpaqueServerFailure>.Err(
                OpaqueServerFailure.KeyExchangeFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToGenerateKE2}: {ex.ResultCode}"));
        }
        catch (ObjectDisposedException)
        {
            authState.Dispose();
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.ServiceDisposed());
        }
        catch (Exception ex)
        {
            authState.Dispose();
            return Result<KE2, OpaqueServerFailure>.Err(OpaqueServerFailure.CryptographicException(ex));
        }
    }

    public Result<SodiumSecureMemoryHandle, OpaqueServerFailure> FinishAuthenticationWithMasterKey(KE3 ke3)
    {
        if (!TryEnsureReady(out OpaqueServerFailure failure))
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(failure);
        }

        if (_currentServerState == null)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput(OpaqueServerConstants.ValidationMessages.NoActiveServerState));
        }

        byte[] sessionKeyBuffer = Array.Empty<byte>();
        byte[] masterKeyBuffer = Array.Empty<byte>();

        try
        {
            DerivedKeys keys = _server!.FinishAuthentication(ke3.Data, _currentServerState);
            sessionKeyBuffer = keys.SessionKey;
            masterKeyBuffer = keys.MasterKey;

            Result<SodiumSecureMemoryHandle, SodiumFailure> masterHandleResult =
                SodiumSecureMemoryHandle.Allocate(OpaqueConstants.MASTER_KEY_LENGTH);

            if (masterHandleResult.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                    OpaqueServerFailure.MemoryAllocationFailed(masterHandleResult.UnwrapErr().Message));
            }

            SodiumSecureMemoryHandle masterHandle = masterHandleResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = masterHandle.Write(masterKeyBuffer);
            if (writeResult.IsErr)
            {
                masterHandle.Dispose();
                return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                    OpaqueServerFailure.MemoryWriteFailed(writeResult.UnwrapErr().Message));
            }

            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Ok(masterHandle);
        }
        catch (ArgumentException ex)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                OpaqueServerFailure.AuthenticationFailed(
                    $"{OpaqueServerConstants.ErrorMessages.FailedToFinishAuthentication}: {ex.ResultCode}"));
        }
        catch (ObjectDisposedException)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                OpaqueServerFailure.ServiceDisposed());
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueServerFailure>.Err(
                OpaqueServerFailure.CryptographicException(ex));
        }
        finally
        {
            ResetServerState();
            if (sessionKeyBuffer.Length > 0)
            {
                CryptographicOperations.ZeroMemory(sessionKeyBuffer);
            }

            if (masterKeyBuffer.Length > 0)
            {
                CryptographicOperations.ZeroMemory(masterKeyBuffer);
            }
        }
    }

    public Result<byte[], OpaqueServerFailure> GetServerPublicKey()
    {
        if (!TryEnsureReady(out OpaqueServerFailure failure))
        {
            return Result<byte[], OpaqueServerFailure>.Err(failure);
        }

        return Result<byte[], OpaqueServerFailure>.Ok(_serverKeys!.GetPublicKeyCopy());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        ResetServer();
        _disposed = true;
    }

    private bool TryEnsureReady(out OpaqueServerFailure failure)
    {
        if (_disposed)
        {
            failure = OpaqueServerFailure.ServiceDisposed();
            return false;
        }

        if (_server == null || _serverKeys == null)
        {
            failure = OpaqueServerFailure.ServiceNotInitialized();
            return false;
        }

        failure = null!;
        return true;
    }

    private void ResetServerState()
    {
        _currentServerState?.Dispose();
        _currentServerState = null;
    }

    private void ResetServer()
    {
        ResetServerState();
        _server?.Dispose();
        _server = null;
        _serverKeys?.Dispose();
        _serverKeys = null;
    }

    private static Result<ServerKeyPair, OpaqueServerFailure> DeriveKeysFromMaterial(string keyMaterial)
    {
        if (string.IsNullOrWhiteSpace(keyMaterial))
        {
            return Result<ServerKeyPair, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput("OPAQUE key seed is required"));
        }

        byte[] seed;
        try
        {
            seed = Convert.FromHexString(keyMaterial);
        }
        catch (Exception ex)
        {
            return Result<ServerKeyPair, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput($"Invalid OPAQUE key seed: {ex.Message}"));
        }

        try
        {
            return Result<ServerKeyPair, OpaqueServerFailure>.Ok(ServerKeyPair.DeriveFromSeed(seed));
        }
        catch (ArgumentException ex)
        {
            return Result<ServerKeyPair, OpaqueServerFailure>.Err(OpaqueServerFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            return Result<ServerKeyPair, OpaqueServerFailure>.Err(
                OpaqueServerFailure.LibraryInitializationFailed($"Failed to derive keys from seed: {ex.ResultCode}"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }
}
