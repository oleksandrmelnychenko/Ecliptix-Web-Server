using Ecliptix.Utilities;
using Ecliptix.Security.Certificate.Pinning.Failures;
using Ecliptix.Security.Certificate.Pinning.Services;
using Serilog;

namespace Ecliptix.Core.Services;

public sealed class CertificatePinningServiceHost(
    CertificatePinningService securityService)
    : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        Result<Unit, CertificatePinningFailure> initResult = await securityService.InitializeAsync();
        if (initResult.IsErr)
        {
            throw new InvalidOperationException($"Server security initialization failed: {initResult.UnwrapErr()}");
        }

        Log.Information("SSL/RSA server security service initialized successfully");
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        securityService.Dispose();
        return Task.CompletedTask;
    }
}