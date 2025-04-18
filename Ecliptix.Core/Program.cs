using System.IO.Compression;
using System.Threading.RateLimiting;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Actors;
using Ecliptix.Core.Interceptors;
using Ecliptix.Core.Protocol;
using Ecliptix.Core.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using OpenTelemetry.Metrics;
using Serilog;
using Serilog.Context;

const string systemActorName = "EcliptixProtocolSystemActor";

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

try
{
    IConfiguration configuration = builder.Configuration
        .SetBasePath(builder.Environment.ContentRootPath)
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
        .AddEnvironmentVariables()
        .Build();

    // Configure services
    builder.Services.AddSingleton<EcliptixSystemIdentityKeys>(sp =>
        EcliptixSystemIdentityKeys.Create(10)
            .Unwrap());

    // Configure services
    RegisterLocalization(builder.Services);
    RegisterValidators(builder.Services);
    RegisterGrpc(builder.Services);

    // Replace default logging with Serilog
    builder.Host.UseSerilog();

    // Add OpenTelemetry with console exporter for testing
    builder.Services.AddOpenTelemetry()
        .WithMetrics(metrics =>
        {
            metrics.AddAspNetCoreInstrumentation();
            metrics.AddConsoleExporter(); // For debugging; replace with OTLP in production
        });

    builder.Services.AddRateLimiter(options =>
    {
        options.AddFixedWindowLimiter(policyName: "grpc", limiterOptions =>
        {
            limiterOptions.PermitLimit = 100; // Allow 100 requests
            limiterOptions.Window = TimeSpan.FromSeconds(10); // Per 10 seconds
            limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 0;
        });
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    });

    builder.Services.AddAkka(systemActorName, (config, sp) =>
    {
        EcliptixSystemIdentityKeys ecliptixSystemIdentityKeys = sp.GetRequiredService<EcliptixSystemIdentityKeys>();
        config.WithActors((system, registry) =>
        {
            ILogger<Program> logger = sp.GetRequiredService<ILogger<Program>>();
            using (LogContext.PushProperty("SystemName", systemActorName))
            {
                logger.LogInformation("Actor system {SystemName} is running");
            }

            TimeSpan defaultCleanupInterval = TimeSpan.FromMinutes(15);
            IActorRef connectionsManagerActor = system.ActorOf(
                EcliptixProtocolConnectionsManagerActor.Build(
                    sp.GetRequiredService<ILogger<EcliptixProtocolConnectionsManagerActor>>(), 
                    defaultCleanupInterval),
                "ConnectionsManager");

            IActorRef protocolSystemActor = system.ActorOf(
                EcliptixProtocolSystemActor.Build(
                    ecliptixSystemIdentityKeys,
                    connectionsManagerActor, 
                    sp.GetRequiredService<ILogger<EcliptixProtocolSystemActor>>()),
                "ProtocolSystem");

            registry.Register<EcliptixProtocolConnectionsManagerActor>(connectionsManagerActor);
            registry.Register<EcliptixProtocolSystemActor>(protocolSystemActor);
        });
    });

    builder.Services.AddHostedService<ActorSystemHostedService>();

    // Configure Kestrel for HTTP/2
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ListenAnyIP(5001, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http2; // Support HTTP/2 only
            // Note: Requires TLS certificate in production
        });
    });

    var app = builder.Build();

    app.UseRateLimiter();
    app.UseHttpsRedirection();
    app.UseRequestLocalization();
    app.UseDefaultFiles();
    app.UseResponseCompression();

    // Top-level route registrations
    app.MapGrpcService<AppDeviceServices>();
    app.MapGet("/", () => Results.Ok("Service up and running"));
    app.MapHealthChecks("/health");

    app.Run();
}
finally
{
    Log.CloseAndFlush();
}

// Service registration methods
static void RegisterLocalization(IServiceCollection services)
{
    services.AddLocalization();
    services.Configure<RequestLocalizationOptions>(options => { options.FallBackToParentUICultures = true; });
}

static void RegisterValidators(IServiceCollection services)
{
    services.AddResponseCompression();
    services.AddHealthChecks();
}

static void RegisterGrpc(IServiceCollection services)
{
    services.AddGrpc(c =>
    {
        c.ResponseCompressionLevel = CompressionLevel.Fastest;
        c.Interceptors.Add<RequestMetaDataInterceptor>();
        c.Interceptors.Add<ThreadCultureInterceptor>();
    });
}

internal class ActorSystemHostedService(ActorSystem actorSystem, ILogger<ActorSystemHostedService> logger)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Actor system hosted service started");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Actor system hosted service stopping suppressor...");
        await actorSystem.Terminate();
        logger.LogInformation("Actor system hosted service stopped");
    }
}