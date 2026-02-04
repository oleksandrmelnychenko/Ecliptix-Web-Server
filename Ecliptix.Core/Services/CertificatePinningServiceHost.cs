using Ecliptix.Core.Configuration.Settings;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.SharedKernel;
using Microsoft.Extensions.Options;

namespace Ecliptix.Core.Services;

public sealed class CertificatePinningServiceHost(
    CertificatePinningService? securityService,
    IOptions<SecurityKeysSettings> securityKeysSettings)
    : IHostedService, IDisposable
{
    private bool _disposed;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (securityService is null)
        {
            throw new InvalidOperationException("CertificatePinningService is not configured");
        }

        SecurityKeysSettings settings = securityKeysSettings.Value;

        Result<Unit, CertificatePinningFailure> initResult;

        if (!string.IsNullOrEmpty(settings.RelayRsaPrivateKeyDer) &&
            !string.IsNullOrEmpty(settings.RelayEd25519PrivateKey))
        {
            byte[] rsaPrivateKeyDer = Convert.FromBase64String(settings.RelayRsaPrivateKeyDer);
            byte[] ed25519PrivateKey = Convert.FromBase64String(settings.RelayEd25519PrivateKey);

            initResult = securityService.InitializeWithKeys(rsaPrivateKeyDer, ed25519PrivateKey);
        }
        else
        {
            initResult = securityService.Initialize();
        }

        if (initResult.IsErr)
        {
            throw new InvalidOperationException($"Server security initialization failed: {initResult.UnwrapErr()}");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Dispose();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            securityService?.Dispose();
            _disposed = true;
        }
    }
}
