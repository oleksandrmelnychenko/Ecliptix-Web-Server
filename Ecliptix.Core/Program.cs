using System.Globalization;
using System.IO.Compression;
using Akka.Actor;
using Akka.Configuration;
using Ecliptix.Core;
using Ecliptix.Core.Interceptors;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Resources;
using Ecliptix.Core.Services;
using Ecliptix.Core.Services.Memberships;
using Ecliptix.Core.Services.Utilities.CipherPayloadHandler;
using Ecliptix.Domain;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Memberships.WorkerActors;
using Ecliptix.Domain.Providers.Twilio;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Context;
using System.Threading.RateLimiting;
using Ecliptix.Core.Protocol.Monitoring;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using HealthStatus = Ecliptix.Core.Json.HealthStatus;

const string systemActorName = "EcliptixProtocolSystemActor";
WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, loggerConfig) =>
{
    string? appInsightsConnectionString = Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING");
    loggerConfig
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services);

    if (!string.IsNullOrEmpty(appInsightsConnectionString))
    {
        loggerConfig.WriteTo.ApplicationInsights(
            new TelemetryConfiguration { ConnectionString = appInsightsConnectionString },
            TelemetryConverter.Traces);
    }
});

try
{
    builder.Services.AddSingleton<IDbConnectionFactory, DbConnectionFactory>();
    builder.Services.AddSingleton<SessionKeepAliveInterceptor>();
    builder.Services.AddSingleton<SecurityInterceptor>();

    RegisterSecurity(builder.Services);
    RegisterLocalization(builder.Services);
    RegisterValidators(builder.Services);
    RegisterGrpc(builder.Services);

    builder.Services.Configure<TwilioSettings>(builder.Configuration.GetSection("TwilioSettings"));
    builder.Services.AddSingleton<ISmsProvider>(serviceProvider =>
    {
        TwilioSettings twilioSettings = serviceProvider.GetRequiredService<IOptions<TwilioSettings>>().Value;
        return new TwilioSmsProvider(twilioSettings);
    });

    builder.Services.AddSingleton<IEcliptixActorRegistry, AotActorRegistry>();
    builder.Services.AddSingleton<ILocalizationProvider, VerificationFlowLocalizer>();
    builder.Services.AddSingleton<IPhoneNumberValidator, PhoneNumberValidator>();
    builder.Services.AddSingleton<IGrpcCipherService, GrpcCipherService<EcliptixProtocolSystemActor>>();
    builder.Services.AddSingleton<IOpaqueProtocolService>(sp =>
    {
        IConfiguration config = sp.GetRequiredService<IConfiguration>();
        string? secretKeySeedBase64 = config["OpaqueProtocol:SecretKeySeed"];

        if (string.IsNullOrEmpty(secretKeySeedBase64))
            throw new InvalidOperationException("OpaqueProtocol:SecretKeySeed configuration is missing.");

        byte[] secretKeySeed;
        try
        {
            secretKeySeed = Convert.FromBase64String(secretKeySeedBase64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                "Invalid OpaqueProtocol:SecretKeySeed format. Must be a valid base64 string.", ex);
        }

        if (secretKeySeed.Length < 32)
            throw new InvalidOperationException("OpaqueProtocol:SecretKeySeed must be at least 32 bytes.");

        return new OpaqueProtocolService(secretKeySeed);
    });

    Config akkaConfig = ConfigurationFactory.Empty
        .WithFallback(ConfigurationFactory.ParseString(File.ReadAllText("akka.conf")));
    ActorSystem actorSystem = ActorSystem.Create(systemActorName, akkaConfig);

    builder.Services.AddSingleton(actorSystem);
    builder.Services.AddHostedService<ActorSystemHostedService>();

    // Add health checks
    builder.Services.AddHealthChecks()
        .AddCheck<Ecliptix.Core.Protocol.Monitoring.ProtocolHealthCheck>("protocol_health");

    WebApplication app = builder.Build();

    app.UseSerilogRequestLogging();
    app.UseRateLimiter();
    app.UseMiddleware<SecurityMiddleware>();
    app.UseMiddleware<IpThrottlingMiddleware>();
    app.UseRequestLocalization();
    app.UseRouting();
    app.UseResponseCompression();
    app.UseDefaultFiles();
    app.UseStaticFiles();

    app.MapGrpcService<AppDeviceServices>();
    app.MapGrpcService<VerificationFlowServices>();
    app.MapGrpcService<MembershipServices>();

    RegisterActors(app.Services.GetRequiredService<ActorSystem>(),
        app.Services.GetRequiredService<IEcliptixActorRegistry>(), app.Services);

    app.MapHealthChecks("/health");
    
    app.MapGet("/metrics", async (IServiceProvider services) =>
    {
        try
        {
            ActorSystem actorSystem = services.GetRequiredService<ActorSystem>();
            ProtocolHealthCheck healthCheck = new(
                actorSystem, 
                services.GetRequiredService<ILogger<ProtocolHealthCheck>>()
            );
            
            HealthCheckResult healthResult = await healthCheck.CheckHealthAsync(new HealthCheckContext());
            HealthMetricsResponse response = new(
                new HealthStatus(
                    healthResult.Status.ToString(),
                    healthResult.Description,
                    healthResult.Data?.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
                ),
                new ProtocolMetrics(
                    "Available",
                    "Protocol metrics collection active",
                    "Full metrics available via actor messages"
                ),
                DateTime.UtcNow
            );
            
            return Results.Json(response, AppJsonSerializerContext.Default.HealthMetricsResponse);
        }
        catch (Exception ex)
        {
            ErrorResponse errorResponse = new(ex.Message);
            return Results.Json(errorResponse, AppJsonSerializerContext.Default.ErrorResponse);
        }
    });
    
    app.MapGet("/", () => Results.Ok(new { Status = "Success", Message = "Server is up and running" }));

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
    services.AddLocalization(options => options.ResourcesPath = "Resources");
    services.Configure<RequestLocalizationOptions>(options =>
    {
        CultureInfo[] supported = [new("en-us"), new("uk-ua")];
        options.DefaultRequestCulture = new RequestCulture("en-us");
        options.SupportedUICultures = supported;
        options.SupportedCultures = supported;
        options.SetDefaultCulture("en-us");
        options.SupportedUICultures = supported;
        options.FallBackToParentUICultures = true;
    });
}

static void RegisterSecurity(IServiceCollection services)
{
    services.AddRateLimiter(options =>
    {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            RateLimitPartition.GetSlidingWindowLimiter(
                partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                factory: _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = 100,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = 4,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 10
                }));

        options.OnRejected = (context, _) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            Log.Warning("Rate limit exceeded for {IpAddress}",
                context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return ValueTask.CompletedTask;
        };
    });

    services.Configure<KestrelServerOptions>(options =>
    {
        options.Limits.MaxRequestBodySize = 10 * 1024 * 1024;
        options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
        options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
        options.Limits.MaxConcurrentConnections = 1000;
        options.Limits.MaxConcurrentUpgradedConnections = 1000;
    });

    services.AddDistributedMemoryCache();
    services.AddHealthChecks();
}

static void RegisterValidators(IServiceCollection services)
{
    services.AddResponseCompression();
}

static void RegisterGrpc(IServiceCollection services)
{
    services.AddGrpc(options =>
    {
        options.ResponseCompressionLevel = CompressionLevel.Fastest;
        options.ResponseCompressionAlgorithm = "gzip";
        options.EnableDetailedErrors = true;
        options.Interceptors.Add<SecurityInterceptor>();
        options.Interceptors.Add<FailureHandlingInterceptor>();
        options.Interceptors.Add<RequestMetaDataInterceptor>();
        options.Interceptors.Add<ThreadCultureInterceptor>();
        options.Interceptors.Add<SessionKeepAliveInterceptor>();
    });
    
    services.Configure<KestrelServerOptions>(options =>
    {
        options.ListenLocalhost(5051, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http2; // gRPC services only
        });
        
        options.ListenLocalhost(8080, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http1; // REST endpoints only
        });
    });
}

static void RegisterActors(ActorSystem system, IEcliptixActorRegistry registry, IServiceProvider serviceProvider)
{
    ILogger<Program> logger = serviceProvider.GetRequiredService<ILogger<Program>>();
    ISmsProvider snsProvider = serviceProvider.GetRequiredService<ISmsProvider>();

    ILocalizationProvider localizationProvider =
        serviceProvider.GetRequiredService<ILocalizationProvider>();

    IOpaqueProtocolService opaqueProtocolService =
        serviceProvider.GetRequiredService<IOpaqueProtocolService>();

    using (LogContext.PushProperty("ActorSystemName", system.Name))
    {
        logger.LogInformation("Actor system {ActorSystemName} is starting up", system.Name);
    }

    IDbConnectionFactory dbDataSource = serviceProvider.GetRequiredService<IDbConnectionFactory>();

    IActorRef protocolSystemActor = system.ActorOf(
        EcliptixProtocolSystemActor.Build(),
        "ProtocolSystem");

    IActorRef appDevicePersistor = system.ActorOf(
        AppDevicePersistorActor.Build(dbDataSource, opaqueProtocolService),
        "AppDevicePersistor");

    IActorRef verificationFlowPersistorActor = system.ActorOf(
        VerificationFlowPersistorActor.Build(dbDataSource),
        "VerificationFlowPersistorActor");

    IActorRef membershipPersistorActor = system.ActorOf(
        MembershipPersistorActor.Build(dbDataSource),
        "MembershipPersistorActor");

    IActorRef membershipActor = system.ActorOf(
        MembershipActor.Build(membershipPersistorActor, opaqueProtocolService, localizationProvider),
        "MembershipActor");

    IActorRef verificationFlowManagerActor = system.ActorOf(
        VerificationFlowManagerActor.Build(verificationFlowPersistorActor, membershipActor,
            snsProvider, localizationProvider),
        "VerificationFlowManagerActor");

    AotActorRegistry aotRegistry = (AotActorRegistry)registry;
    aotRegistry.Register(ActorIds.EcliptixProtocolSystemActor, protocolSystemActor);
    aotRegistry.Register(ActorIds.AppDevicePersistorActor, appDevicePersistor);
    aotRegistry.Register(ActorIds.VerificationFlowPersistorActor, verificationFlowPersistorActor);
    aotRegistry.Register(ActorIds.VerificationFlowManagerActor, verificationFlowManagerActor);
    aotRegistry.Register(ActorIds.MembershipPersistorActor, membershipPersistorActor);
    aotRegistry.Register(ActorIds.MembershipActor, membershipActor);

    logger.LogInformation("Registered top-level actors: {ProtocolActorPath}, {PersistorActorPath}",
        protocolSystemActor.Path, appDevicePersistor.Path);
}

internal class ActorSystemHostedService(ActorSystem actorSystem) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service started");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service initiating shutdown...");
        await CoordinatedShutdown.Get(actorSystem).Run(CoordinatedShutdown.ClrExitReason.Instance);
        Log.Information("Actor system hosted service shutdown complete");
    }
}