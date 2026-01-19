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

    public Result<Unit, OpaqueServerFailure> Initialize(IReadOnlyDictionary<int, string> keyRing, int activeKeyVersion)
    {
        if (keyRing.Count == 0)
        {
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput("OPAQUE key ring is empty"));
        }

        if (!keyRing.ContainsKey(activeKeyVersion))
        {
            return Result<Unit, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput(
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
                return Result<Unit, OpaqueServerFailure>.Err(
                    OpaqueServerFailure.InvalidInput($"Invalid OPAQUE key version: {entry.Key}"));
            }

            if (string.IsNullOrWhiteSpace(entry.Value))
            {
                DisposeServices();
                _services.Clear();
                return Result<Unit, OpaqueServerFailure>.Err(
                    OpaqueServerFailure.InvalidInput($"OPAQUE key seed missing for version {entry.Key}"));
            }

            OpaqueProtocolService service = new();
            Result<Unit, OpaqueServerFailure> initResult = service.Initialize(entry.Value);
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
        return Result<Unit, OpaqueServerFailure>.Ok(Unit.Value);
    }

    public Result<RegistrationResponse, OpaqueServerFailure> CreateRegistrationResponse(
        RegistrationRequest request,
        Guid accountId,
        int? keyVersion = null)
    {
        int version = keyVersion ?? ActiveKeyVersion;
        Result<OpaqueProtocolService, OpaqueServerFailure> serviceResult = GetService(version);
        return serviceResult.IsErr
            ? Result<RegistrationResponse, OpaqueServerFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().CreateRegistrationResponse(request, accountId);
    }

    public Result<KE2, OpaqueServerFailure> GenerateKe2(
        KE1 ke1,
        Guid accountId,
        byte[] registrationRecord,
        int keyVersion)
    {
        Result<OpaqueProtocolService, OpaqueServerFailure> serviceResult = GetService(keyVersion);
        return serviceResult.IsErr
            ? Result<KE2, OpaqueServerFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().GenerateKe2(ke1, accountId, registrationRecord);
    }

    public Result<(SodiumSecureMemoryHandle SessionKey, SodiumSecureMemoryHandle MasterKey), OpaqueServerFailure>
        FinishAuthenticationWithMasterKey(KE3 ke3, int keyVersion)
    {
        Result<OpaqueProtocolService, OpaqueServerFailure> serviceResult = GetService(keyVersion);
        return serviceResult.IsErr
            ? Result<(SodiumSecureMemoryHandle, SodiumSecureMemoryHandle), OpaqueServerFailure>.Err(
                serviceResult.UnwrapErr())
            : serviceResult.Unwrap().FinishAuthenticationWithMasterKey(ke3);
    }

    public Result<byte[], OpaqueServerFailure> GetServerPublicKey(int? keyVersion = null)
    {
        int version = keyVersion ?? ActiveKeyVersion;
        Result<OpaqueProtocolService, OpaqueServerFailure> serviceResult = GetService(version);
        return serviceResult.IsErr
            ? Result<byte[], OpaqueServerFailure>.Err(serviceResult.UnwrapErr())
            : serviceResult.Unwrap().GetServerPublicKey();
    }

    public void Dispose()
    {
        DisposeServices();
        _services.Clear();
    }

    private Result<OpaqueProtocolService, OpaqueServerFailure> GetService(int keyVersion)
    {
        if (_services.Count == 0)
        {
            return Result<OpaqueProtocolService, OpaqueServerFailure>.Err(
                OpaqueServerFailure.ServiceNotInitialized());
        }

        return _services.TryGetValue(keyVersion, out OpaqueProtocolService? service)
            ? Result<OpaqueProtocolService, OpaqueServerFailure>.Ok(service)
            : Result<OpaqueProtocolService, OpaqueServerFailure>.Err(
                OpaqueServerFailure.InvalidInput($"OPAQUE key version {keyVersion} is not available"));
    }

    private void DisposeServices()
    {
        foreach (OpaqueProtocolService service in _services.Values)
        {
            service.Dispose();
        }
    }
}
