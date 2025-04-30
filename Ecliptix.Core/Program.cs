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

    RegisterLocalization(builder.Services);
    RegisterValidators(builder.Services);
    RegisterGrpc(builder.Services);

    builder.Host.UseSerilog();

    builder.Services.AddOpenTelemetry()
        .WithMetrics(metrics =>
        {
            metrics.AddAspNetCoreInstrumentation();
            metrics.AddConsoleExporter();
        });

    /*builder.Services.AddRateLimiter(options =>
    {
        options.AddFixedWindowLimiter(policyName: "grpc", limiterOptions =>
        {
            limiterOptions.PermitLimit = 100;
            limiterOptions.Window = TimeSpan.FromSeconds(10);
            limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 0;
        });
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    });*/

    builder.Services.AddAkka(systemActorName, (config, sp) =>
    {
        config.WithActors((system, registry) =>
        {
            ILogger<Program> logger = sp.GetRequiredService<ILogger<Program>>();
            using (LogContext.PushProperty("SystemName", systemActorName))
            {
                logger.LogInformation("$Actor system {systemActorName} is running");
            }

            IActorRef protocolSystemActor = system.ActorOf(
                EcliptixProtocolSystemActor.Build(sp.GetRequiredService<ILogger<EcliptixProtocolSystemActor>>()),
                "ProtocolSystem");

            registry.Register<EcliptixProtocolSystemActor>(protocolSystemActor);
        });
    });

    builder.Services.AddHostedService<ActorSystemHostedService>();
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.ListenAnyIP(5001, listenOptions => { listenOptions.Protocols = HttpProtocols.Http2; });
    });

    WebApplication app = builder.Build();

    app.UseHttpsRedirection();
    app.UseRequestLocalization();
    app.UseDefaultFiles();
    app.UseResponseCompression();

    app.MapGrpcService<AppDeviceServices>();
    app.MapGet("/", () => Results.Ok("Service up and running"));
    app.MapHealthChecks("/health");

    app.Run();
}
finally
{
    Log.CloseAndFlush();
}

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