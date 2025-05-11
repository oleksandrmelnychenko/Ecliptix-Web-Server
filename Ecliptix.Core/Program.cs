using System.IO.Compression;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Interceptors;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Services;
using Ecliptix.Core.Services.Memberships;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Persistors;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Npgsql;
using OpenTelemetry.Metrics;
using Serilog;
using Serilog.Context;
using Microsoft.Extensions.Diagnostics.HealthChecks;

const string systemActorName = "EcliptixProtocolSystemActor";

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Host.UseSerilog();

try
{
    IConfiguration configuration = builder.Configuration;

    string? connectionString = configuration.GetConnectionString("EcliptixDb");
    if (string.IsNullOrEmpty(connectionString))
    {
        throw new InvalidOperationException("Connection string 'EcliptixDb' not found or is empty in configuration.");
    }

    builder.Services.AddSingleton<SNSProvider>();
    builder.Services.AddSingleton<NpgsqlDataSource>(sp =>
    {
        ILoggerFactory? loggerFactory = sp.GetService<ILoggerFactory>();
        NpgsqlDataSourceBuilder dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
        if (loggerFactory != null)
        {
            dataSourceBuilder.UseLoggerFactory(loggerFactory);
        }
        else
        {
            Log.Warning("ILoggerFactory not found in service provider. Npgsql logging will be disabled.");
        }

        Log.Information("Building NpgsqlDataSource for EcliptixDb.");
        return dataSourceBuilder.Build();
    });

    RegisterLocalization(builder.Services);
    RegisterValidators(builder.Services);
    RegisterGrpc(builder.Services);

    builder.Services.AddOpenTelemetry()
        .WithMetrics(metrics =>
        {
            metrics.AddAspNetCoreInstrumentation();
            metrics.AddConsoleExporter();
        });

    builder.Services.AddAkka(systemActorName, (akkaBuilder, serviceProvider) =>
    {
        akkaBuilder.WithActors((system, registry) =>
        {
            ILogger<Program> logger = serviceProvider.GetRequiredService<ILogger<Program>>();

            using (LogContext.PushProperty("ActorSystemName", system.Name))
            {
                logger.LogInformation("Actor system {ActorSystemName} is starting up.", system.Name);
            }

            NpgsqlDataSource npgsqlDataSource = serviceProvider.GetRequiredService<NpgsqlDataSource>();
            SNSProvider snsProvider = serviceProvider.GetRequiredService<SNSProvider>();

            ILogger<EcliptixProtocolSystemActor> protocolActorLogger =
                serviceProvider.GetRequiredService<ILogger<EcliptixProtocolSystemActor>>();

            IActorRef protocolSystemActor = system.ActorOf(
                EcliptixProtocolSystemActor.Build(protocolActorLogger),
                "ProtocolSystem");

            IActorRef appDevicePersistor = system.ActorOf(
                AppDevicePersistorActor.Build(npgsqlDataSource),
                "AppDevicePersistor");

            IActorRef membershipVerificationSessionPersistorActor = system.ActorOf(
                VerificationSessionPersistorActor.Build(npgsqlDataSource),
                "MembershipVerificationSessionPersistorActor");

            IActorRef verificationSessionManagerActor = system.ActorOf(
                VerificationSessionManagerActor.Build(membershipVerificationSessionPersistorActor,
                    snsProvider),
                "VerificationSessionManagerActor");

            registry.Register<EcliptixProtocolSystemActor>(protocolSystemActor);
            registry.Register<AppDevicePersistorActor>(appDevicePersistor);
            registry.Register<VerificationSessionPersistorActor>(membershipVerificationSessionPersistorActor);
            registry.Register<VerificationSessionManagerActor>(verificationSessionManagerActor);

            logger.LogInformation("Registered top-level actors: {ProtocolActorPath}, {PersistorActorPath}",
                protocolSystemActor.Path, appDevicePersistor.Path);
        });
    });

    builder.Services.AddHostedService<ActorSystemHostedService>();

    builder.WebHost.ConfigureKestrel(options =>
    {
        int grpcPort = configuration.GetValue("GrpcServer:Port", 5001);
        options.ListenAnyIP(grpcPort, listenOptions => { listenOptions.Protocols = HttpProtocols.Http2; });
        options.ListenAnyIP(5002);
    });

    WebApplication app = builder.Build();

    app.UseSerilogRequestLogging();
    // app.UseRateLimiter();
    // app.UseHttpsRedirection();
    app.UseRequestLocalization();
    app.UseRouting();
    app.UseResponseCompression();
    app.UseDefaultFiles();
    app.UseStaticFiles();

    app.MapGrpcService<AppDeviceServices>();
    app.MapGrpcService<VerificationServices>();

    // .RequireRateLimiting("grpc");

    app.MapGet("/", () => Results.Ok("Ecliptix Service is operational."));
    app.MapHealthChecks("/healthz");

    Log.Information("Starting Ecliptix application host");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Ecliptix application host terminated unexpectedly");
    throw;
}
finally
{
    Log.Information("Shutting down Ecliptix application host");
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
    services.AddHealthChecks()
        .AddNpgSql(
            sp => sp.GetRequiredService<NpgsqlDataSource>(),
            name: "database_status",
            failureStatus: HealthStatus.Unhealthy,
            tags: ["db", "postgresql"]);
}

static void RegisterGrpc(IServiceCollection services)
{
    services.AddGrpc(options =>
    {
        options.ResponseCompressionLevel = CompressionLevel.Fastest;
        options.EnableDetailedErrors = true;
        options.Interceptors.Add<RequestMetaDataInterceptor>();
        options.Interceptors.Add<ThreadCultureInterceptor>();
    });
}

internal class ActorSystemHostedService(ActorSystem actorSystem, ILogger<ActorSystemHostedService> logger)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Actor system hosted service started ()");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Actor system hosted service initiating shutdown...");
        await CoordinatedShutdown.Get(actorSystem).Run(CoordinatedShutdown.ClrExitReason.Instance);
        logger.LogInformation("Actor system hosted service shutdown complete.");
    }
}