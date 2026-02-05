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
    private OpaqueRelay? _relay;
    private AuthenticationState? _currentRelayState;
    private RelayKeyPair? _relayKeys;
    private bool _disposed;

    public Result<Unit, OpaqueRelayFailure> Initialize(string secretKeySeed)
    {
        if (_disposed)
        {
            return Result<Unit, OpaqueRelayFailure>.Err(OpaqueRelayFailure.ServiceDisposed());
        }

        ResetRelay();

        Result<RelayKeyPair, OpaqueRelayFailure> keyResult = DeriveKeysFromMaterial(secretKeySeed);
        if (keyResult.IsErr)
        {
            return Result<Unit, OpaqueRelayFailure>.Err(keyResult.UnwrapErr());
        }

        _relayKeys = keyResult.Unwrap();

        try
        {
            _relay = OpaqueRelay.Create(_relayKeys);
            return Result<Unit, OpaqueRelayFailure>.Ok(Unit.Value);
        }
        catch (OpaqueException ex)
        {
            ResetRelay();
            return Result<Unit, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.LibraryInitializationFailed(
                    $"{OpaqueRelayConstants.ErrorMessages.FailedToCreateRelay}: {ex.ResultCode}"));
        }
        catch (ArgumentException ex)
        {
            ResetRelay();
            return Result<Unit, OpaqueRelayFailure>.Err(OpaqueRelayFailure.InvalidInput(ex.Message));
        }
        catch (Exception ex)
        {
            ResetRelay();
            return Result<Unit, OpaqueRelayFailure>.Err(OpaqueRelayFailure.InitializationException(ex));
        }
    }

    public Result<RegistrationResponse, OpaqueRelayFailure>
        CreateRegistrationResponse(RegistrationRequest request, Guid accountId)
    {
        if (!TryEnsureReady(out OpaqueRelayFailure failure))
        {
            return Result<RegistrationResponse, OpaqueRelayFailure>.Err(failure);
        }

        byte[] accountIdBytes = accountId.ToByteArray();

        try
        {
            byte[] responseBuffer = _relay!.CreateRegistrationResponse(request.Data, accountIdBytes);
            Result<RegistrationResponse, OpaqueRelayFailure> registrationResult =
                RegistrationResponse.Create(responseBuffer);

            return registrationResult.IsErr
                ? Result<RegistrationResponse, OpaqueRelayFailure>.Err(registrationResult.UnwrapErr())
                : Result<RegistrationResponse, OpaqueRelayFailure>.Ok(registrationResult.Unwrap());
        }
        catch (ArgumentException ex)
        {
            return Result<RegistrationResponse, OpaqueRelayFailure>.Err(OpaqueRelayFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            return Result<RegistrationResponse, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.RegistrationFailed(
                    $"{OpaqueRelayConstants.ErrorMessages.FailedToCreateRegistrationResponse}: {ex.ResultCode}"));
        }
        catch (ObjectDisposedException)
        {
            return Result<RegistrationResponse, OpaqueRelayFailure>.Err(OpaqueRelayFailure.ServiceDisposed());
        }
        catch (Exception ex)
        {
            return Result<RegistrationResponse, OpaqueRelayFailure>.Err(OpaqueRelayFailure.CryptographicException(ex));
        }
    }

    public Result<KE2, OpaqueRelayFailure> GenerateKe2(KE1 ke1, Guid accountId, byte[] registrationRecord)
    {
        if (!TryEnsureReady(out OpaqueRelayFailure failure))
        {
            return Result<KE2, OpaqueRelayFailure>.Err(failure);
        }

        ResetRelayState();

        byte[] accountIdBytes = accountId.ToByteArray();
        AuthenticationState authState;
        try
        {
            authState = AuthenticationState.Create();
        }
        catch (OpaqueException ex)
        {
            return Result<KE2, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.KeyExchangeFailed(
                    $"{OpaqueRelayConstants.ErrorMessages.FailedToCreateRelayState}: {ex.ResultCode}"));
        }
        catch (Exception ex)
        {
            return Result<KE2, OpaqueRelayFailure>.Err(OpaqueRelayFailure.CryptographicException(ex));
        }

        try
        {
            byte[] ke2Buffer = _relay!.GenerateKe2(
                ke1.Data,
                accountIdBytes,
                registrationRecord,
                authState);

            Result<KE2, OpaqueRelayFailure> ke2Result = KE2.Create(ke2Buffer);
            if (ke2Result.IsErr)
            {
                authState.Dispose();
                return Result<KE2, OpaqueRelayFailure>.Err(ke2Result.UnwrapErr());
            }

            _currentRelayState = authState;
            return Result<KE2, OpaqueRelayFailure>.Ok(ke2Result.Unwrap());
        }
        catch (ArgumentException ex)
        {
            authState.Dispose();
            return Result<KE2, OpaqueRelayFailure>.Err(OpaqueRelayFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            authState.Dispose();
            return Result<KE2, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.KeyExchangeFailed(
                    $"{OpaqueRelayConstants.ErrorMessages.FailedToGenerateKE2}: {ex.ResultCode}"));
        }
        catch (ObjectDisposedException)
        {
            authState.Dispose();
            return Result<KE2, OpaqueRelayFailure>.Err(OpaqueRelayFailure.ServiceDisposed());
        }
        catch (Exception ex)
        {
            authState.Dispose();
            return Result<KE2, OpaqueRelayFailure>.Err(OpaqueRelayFailure.CryptographicException(ex));
        }
    }

    public Result<SodiumSecureMemoryHandle, OpaqueRelayFailure> FinishAuthenticationWithMasterKey(KE3 ke3)
    {
        if (!TryEnsureReady(out OpaqueRelayFailure failure))
        {
            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(failure);
        }

        if (_currentRelayState == null)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput(OpaqueRelayConstants.ValidationMessages.NoActiveRelayState));
        }

        byte[] sessionKeyBuffer = Array.Empty<byte>();
        byte[] masterKeyBuffer = Array.Empty<byte>();

        try
        {
            DerivedKeys keys = _relay!.FinishAuthentication(ke3.Data, _currentRelayState);
            sessionKeyBuffer = keys.SessionKey;
            masterKeyBuffer = keys.MasterKey;

            Result<SodiumSecureMemoryHandle, SodiumFailure> masterHandleResult =
                SodiumSecureMemoryHandle.Allocate(OpaqueConstants.MASTER_KEY_LENGTH);

            if (masterHandleResult.IsErr)
            {
                return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                    OpaqueRelayFailure.MemoryAllocationFailed(masterHandleResult.UnwrapErr().Message));
            }

            SodiumSecureMemoryHandle masterHandle = masterHandleResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = masterHandle.Write(masterKeyBuffer);
            if (writeResult.IsErr)
            {
                masterHandle.Dispose();
                return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                    OpaqueRelayFailure.MemoryWriteFailed(writeResult.UnwrapErr().Message));
            }

            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Ok(masterHandle);
        }
        catch (ArgumentException ex)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.AuthenticationFailed(
                    $"{OpaqueRelayConstants.ErrorMessages.FailedToFinishAuthentication}: {ex.ResultCode}"));
        }
        catch (ObjectDisposedException)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.ServiceDisposed());
        }
        catch (Exception ex)
        {
            return Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.CryptographicException(ex));
        }
        finally
        {
            ResetRelayState();
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

    public Result<byte[], OpaqueRelayFailure> GetRelayPublicKey()
    {
        if (!TryEnsureReady(out OpaqueRelayFailure failure))
        {
            return Result<byte[], OpaqueRelayFailure>.Err(failure);
        }

        return Result<byte[], OpaqueRelayFailure>.Ok(_relayKeys!.GetPublicKeyCopy());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        ResetRelay();
        _disposed = true;
    }

    private bool TryEnsureReady(out OpaqueRelayFailure failure)
    {
        if (_disposed)
        {
            failure = OpaqueRelayFailure.ServiceDisposed();
            return false;
        }

        if (_relay == null || _relayKeys == null)
        {
            failure = OpaqueRelayFailure.ServiceNotInitialized();
            return false;
        }

        failure = null!;
        return true;
    }

    private void ResetRelayState()
    {
        _currentRelayState?.Dispose();
        _currentRelayState = null;
    }

    private void ResetRelay()
    {
        ResetRelayState();
        _relay?.Dispose();
        _relay = null;
        _relayKeys?.Dispose();
        _relayKeys = null;
    }

    private static Result<RelayKeyPair, OpaqueRelayFailure> DeriveKeysFromMaterial(string keyMaterial)
    {
        if (string.IsNullOrWhiteSpace(keyMaterial))
        {
            return Result<RelayKeyPair, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput("OPAQUE key seed is required"));
        }

        byte[] seed;
        try
        {
            seed = Convert.FromHexString(keyMaterial);
        }
        catch (Exception ex)
        {
            return Result<RelayKeyPair, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput($"Invalid OPAQUE key seed: {ex.Message}"));
        }

        try
        {
            return Result<RelayKeyPair, OpaqueRelayFailure>.Ok(RelayKeyPair.DeriveFromSeed(seed));
        }
        catch (ArgumentException ex)
        {
            return Result<RelayKeyPair, OpaqueRelayFailure>.Err(OpaqueRelayFailure.InvalidInput(ex.Message));
        }
        catch (OpaqueException ex)
        {
            return Result<RelayKeyPair, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.LibraryInitializationFailed($"Failed to derive keys from seed: {ex.ResultCode}"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }
}
