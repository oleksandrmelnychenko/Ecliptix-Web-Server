using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.SharedKernel;

namespace Ecliptix.Core.Services;

public sealed class CertificatePinningServiceHost(
    CertificatePinningService? securityService)
    : IHostedService, IDisposable
{
    private bool _disposed;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (securityService is null)
        {
            throw new InvalidOperationException("CertificatePinningService is not configured");
        }

        Result<Unit, CertificatePinningFailure> initResult = securityService.Initialize();
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
