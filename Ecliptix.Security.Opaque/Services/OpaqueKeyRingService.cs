using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Models.AuthenticationMessages;
using Ecliptix.Security.Opaque.Models.RegistrationMessages;
using Ecliptix.SharedKernel;

namespace Ecliptix.Security.Opaque.Services;

public sealed class OpaqueKeyRingService : IOpaqueKeyRingService, IDisposable
{
    private readonly Dictionary<int, OpaqueProtocolService> _services = new();

    public int ActiveKeyVersion { get; private set; }

    public Result<Unit, OpaqueRelayFailure> Initialize(IReadOnlyDictionary<int, string> keyRing, int activeKeyVersion)
    {
        if (keyRing.Count == 0)
        {
            return Result<Unit, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput("OPAQUE key ring is empty"));
        }

        if (!keyRing.ContainsKey(activeKeyVersion))
        {
            return Result<Unit, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput(
                    $"Active OPAQUE key version {activeKeyVersion} is missing from the key ring"));
        }

        DisposeServices();
        _services.Clear();

        foreach (KeyValuePair<int, string> entry in keyRing)
        {
            if (entry.Key <= 0)
            {
                DisposeServices();
                _services.Clear();
                return Result<Unit, OpaqueRelayFailure>.Err(
                    OpaqueRelayFailure.InvalidInput($"Invalid OPAQUE key version: {entry.Key}"));
            }

            if (string.IsNullOrWhiteSpace(entry.Value))
            {
                DisposeServices();
                _services.Clear();
                return Result<Unit, OpaqueRelayFailure>.Err(
                    OpaqueRelayFailure.InvalidInput($"OPAQUE key seed missing for version {entry.Key}"));
            }

            OpaqueProtocolService service = new();
            Result<Unit, OpaqueRelayFailure> initResult = service.Initialize(entry.Value);
            if (initResult.IsErr)
            {
                service.Dispose();
                DisposeServices();
                _services.Clear();
                return initResult;
            }

            _services[entry.Key] = service;
        }

        ActiveKeyVersion = activeKeyVersion;
        return Result<Unit, OpaqueRelayFailure>.Ok(Unit.Value);
    }

    public Result<RegistrationResponse, OpaqueRelayFailure> CreateRegistrationResponse(
        RegistrationRequest request,
        Guid accountId,
        int? keyVersion = null)
    {
        int version = keyVersion ?? ActiveKeyVersion;
        Result<OpaqueProtocolService, OpaqueRelayFailure> serviceResult = GetService(version);
        return serviceResult.IsErr
            ? Result<RegistrationResponse, OpaqueRelayFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().CreateRegistrationResponse(request, accountId);
    }

    public Result<KE2, OpaqueRelayFailure> GenerateKe2(
        KE1 ke1,
        Guid accountId,
        byte[] registrationRecord,
        int keyVersion)
    {
        Result<OpaqueProtocolService, OpaqueRelayFailure> serviceResult = GetService(keyVersion);
        return serviceResult.IsErr
            ? Result<KE2, OpaqueRelayFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().GenerateKe2(ke1, accountId, registrationRecord);
    }

    public Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>
        FinishAuthenticationWithMasterKey(KE3 ke3, int keyVersion)
    {
        Result<OpaqueProtocolService, OpaqueRelayFailure> serviceResult = GetService(keyVersion);
        return serviceResult.IsErr
            ? Result<SodiumSecureMemoryHandle, OpaqueRelayFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().FinishAuthenticationWithMasterKey(ke3);
    }

    public Result<byte[], OpaqueRelayFailure> GetRelayPublicKey(int? keyVersion = null)
    {
        int version = keyVersion ?? ActiveKeyVersion;
        Result<OpaqueProtocolService, OpaqueRelayFailure> serviceResult = GetService(version);
        return serviceResult.IsErr
            ? Result<byte[], OpaqueRelayFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().GetRelayPublicKey();
    }

    public void Dispose()
    {
        DisposeServices();
        _services.Clear();
    }

    private Result<OpaqueProtocolService, OpaqueRelayFailure> GetService(int keyVersion)
    {
        if (_services.Count == 0)
        {
            return Result<OpaqueProtocolService, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.ServiceNotInitialized());
        }

        return _services.TryGetValue(keyVersion, out OpaqueProtocolService? service)
            ? Result<OpaqueProtocolService, OpaqueRelayFailure>.Ok(service)
            : Result<OpaqueProtocolService, OpaqueRelayFailure>.Err(
                OpaqueRelayFailure.InvalidInput($"OPAQUE key version {keyVersion} is not available"));
    }

    private void DisposeServices()
    {
        foreach (OpaqueProtocolService service in _services.Values)
        {
            service.Dispose();
        }
    }
}
