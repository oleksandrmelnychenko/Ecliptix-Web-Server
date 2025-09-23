using Ecliptix.Domain.Utilities;
using Ecliptix.Security.SSL.Native.Services;
using Ecliptix.Security.SSL.Native.Failures;

namespace Ecliptix.Core.Services;

public sealed class ServerSecurityInitializationService : IHostedService
{
    private readonly ServerSecurityService _securityService;
    private readonly ILogger<ServerSecurityInitializationService> _logger;
    private readonly IConfiguration _configuration;

    public ServerSecurityInitializationService(
        ServerSecurityService securityService,
        ILogger<ServerSecurityInitializationService> logger,
        IConfiguration configuration)
    {
        _securityService = securityService;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initializing server security service");

        string privateKeyPath = _configuration["SecurityKeys:ServerPrivateKeyPath"] ??
                                Path.Combine(AppContext.BaseDirectory, "server_private.pem");

        if (!File.Exists(privateKeyPath))
        {
            _logger.LogCritical("Server private key file not found at: {KeyPath}", privateKeyPath);
            throw new FileNotFoundException($"Server private key file not found at: {privateKeyPath}");
        }

        string privateKeyPem = await File.ReadAllTextAsync(privateKeyPath, cancellationToken);
        _logger.LogInformation("Server private key loaded from: {KeyPath}", privateKeyPath);

        Result<Unit, ServerSecurityFailure> initResult = await _securityService.InitializeWithKeyAsync(privateKeyPem);
        if (initResult.IsErr)
        {
            _logger.LogCritical("Server security initialization failed: {Error}", initResult.UnwrapErr().Message);
            throw new InvalidOperationException($"Server security initialization failed: {initResult.UnwrapErr()}");
        }

        _logger.LogInformation("Server security service initialized successfully with private key");

        await RunSelfTestAsync();

        _logger.LogInformation("Server security service ready");
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Shutting down server security service");
        _securityService.Dispose();
        return Task.CompletedTask;
    }

    private async Task RunSelfTestAsync()
    {
        _logger.LogInformation("Starting server security self-test");

        byte[] testMessage = "SSL Server Self-Test Message"u8.ToArray();

        Result<byte[], ServerSecurityFailure> signResult = await _securityService.SignAsync(testMessage);
        if (signResult.IsErr)
        {
            throw new InvalidOperationException("Server security self-test failed - signing");
        }

        _logger.LogInformation("Server security self-test completed successfully - signing verification passed");
    }
}