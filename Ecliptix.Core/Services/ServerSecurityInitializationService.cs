using Ecliptix.Domain.Utilities;
using Ecliptix.Security.SSL.Native.Services;
using Ecliptix.Security.SSL.Native.Failures;
using Serilog;

namespace Ecliptix.Core.Services;

public sealed class ServerSecurityInitializationService(
    ServerSecurityService securityService,
    IConfiguration configuration)
    : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        Log.Information("Initializing server security service");

        string privateKeyPath = configuration["SecurityKeys:ServerPrivateKeyPath"] ??
                                Path.Combine(AppContext.BaseDirectory, "server_private.pem");

        if (!File.Exists(privateKeyPath))
        {
            Log.Error("Server private key file not found at: {KeyPath}", privateKeyPath);
            throw new FileNotFoundException($"Server private key file not found at: {privateKeyPath}");
        }

        string privateKeyPem = await File.ReadAllTextAsync(privateKeyPath, cancellationToken);
        Log.Information("Server private key loaded from: {KeyPath}", privateKeyPath);

        Result<Unit, ServerSecurityFailure> initResult = await securityService.InitializeWithKeyAsync(privateKeyPem);
        if (initResult.IsErr)
        {
            Log.Error("Server security initialization failed: {Error}", initResult.UnwrapErr().Message);
            throw new InvalidOperationException($"Server security initialization failed: {initResult.UnwrapErr()}");
        }

        Log.Information("Server security service initialized successfully with private key");

        await RunSelfTestAsync();

        Log.Information("Server security service ready");
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Information("Shutting down server security service");
        securityService.Dispose();
        return Task.CompletedTask;
    }

    private async Task RunSelfTestAsync()
    {
        Log.Information("Starting server security self-test");

        byte[] testMessage = "SSL Server Self-Test Message"u8.ToArray();

        Result<byte[], ServerSecurityFailure> signResult = await securityService.SignAsync(testMessage);
        if (signResult.IsErr)
        {
            throw new InvalidOperationException("Server security self-test failed - signing");
        }

        Log.Information("Server security self-test completed successfully - signing verification passed");
    }
}