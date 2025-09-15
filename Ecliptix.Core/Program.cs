using System.Globalization;
using System.IO.Compression;
using System.Text;
using Akka;
using Akka.Actor;
using Akka.Configuration;
using Ecliptix.Core;
using Ecliptix.Core.Infrastructure.Grpc.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware;
using Ecliptix.Core.Domain.Actors;
using Ecliptix.Core.Resources;
using Microsoft.Extensions.ObjectPool;
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
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using Serilog;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using HealthStatus = Ecliptix.Core.Json.HealthStatus;
using Ecliptix.Core.Domain.Protocol.Monitoring;
using Ecliptix.Core.Api.Grpc.Services.Authentication;
using Ecliptix.Core.Api.Grpc.Services.Membership;
using Ecliptix.Core.Api.Grpc.Services.Device;
using Ecliptix.Core.Infrastructure.DbUp;
using Microsoft.Extensions.Primitives;
using Serilog.Context;

const string systemActorName = "EcliptixProtocolSystemActor";
WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, loggerConfig) =>
{
    string? appInsightsConnectionString = Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING");

    loggerConfig
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithProperty("Environment", context.HostingEnvironment.EnvironmentName);

    
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
    builder.Services.AddSingleton<TelemetryInterceptor>();
    builder.Services.AddSingleton<ConnectionMonitoringInterceptor>();
    builder.Services.AddSingleton<FailureHandlingInterceptor>();
    builder.Services.AddSingleton<RequestMetaDataInterceptor>();
    builder.Services.AddSingleton<ThreadCultureInterceptor>();

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

    builder.Services.AddSingleton<IEcliptixActorRegistry, ActorRegistry>();
    builder.Services.AddSingleton<ILocalizationProvider, VerificationFlowLocalizer>();
    builder.Services.AddSingleton<IPhoneNumberValidator, PhoneNumberValidator>();
    builder.Services.AddSingleton<IGrpcCipherService, GrpcCipherService<EcliptixProtocolSystemActor>>();

    builder.Services.AddSingleton<ObjectPool<StringBuilder>>(_ =>
    {
        DefaultObjectPoolProvider provider = new();
        return provider.CreateStringBuilderPool();
    });

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

    builder.Services.AddHealthChecks()
        .AddCheck<ProtocolHealthCheck>("protocol_health")
        .AddCheck<VerificationFlowHealthCheck>("verification_flow_health")
        .AddCheck<DatabaseHealthCheck>("database_health");

    WebApplication app = builder.Build();

    app.UseSerilogRequestLogging(options =>
    {
        options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
        options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
        {
            diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value!);
            diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].ToString());
            diagnosticContext.Set("Protocol", httpContext.Request.Protocol);

            if (httpContext.Request.Headers.TryGetValue("X-Connect-Id", out StringValues connectId))
            {
                diagnosticContext.Set("ConnectId", connectId.ToString());
            }

            if (httpContext.Request.ContentLength.HasValue)
            {
                diagnosticContext.Set("RequestSize", httpContext.Request.ContentLength.Value);
            }
        };
    });
    
   
    app.UseRateLimiter();
    app.UseMiddleware<SecurityMiddleware>();
    app.UseMiddleware<IpThrottlingMiddleware>();
    app.UseRequestLocalization();
    app.UseRouting();
    app.UseResponseCompression();
    app.UseDefaultFiles();
    app.UseStaticFiles();

    app.MapGrpcService<DeviceGrpcService>();
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
            ProtocolHealthCheck healthCheck = new(actorSystem);

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
        options.Interceptors.Add<RequestMetaDataInterceptor>();
        options.Interceptors.Add<SessionKeepAliveInterceptor>();
        options.Interceptors.Add<TelemetryInterceptor>();
        options.Interceptors.Add<ThreadCultureInterceptor>();
        options.Interceptors.Add<FailureHandlingInterceptor>();
    });

    services.Configure<KestrelServerOptions>(options =>
    {
        options.ListenAnyIP(5051, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http2;
        });

        options.ListenAnyIP(8080, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http1;
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

    IActorRef authContextPersistorActor = system.ActorOf(
        AuthContextPersistorActor.Build(dbDataSource),
        "AuthContextPersistorActor");

    IActorRef authenticationStateManager = system.ActorOf(
        AuthenticationStateManager.Build(),
        "AuthenticationStateManager");

    IActorRef membershipActor = system.ActorOf(
        MembershipActor.Build(membershipPersistorActor, authContextPersistorActor, opaqueProtocolService, localizationProvider, authenticationStateManager),
        "MembershipActor");

    IActorRef verificationFlowManagerActor = system.ActorOf(
        VerificationFlowManagerActor.Build(verificationFlowPersistorActor, membershipActor,
            snsProvider, localizationProvider),
        "VerificationFlowManagerActor");

    registry.Register(ActorIds.EcliptixProtocolSystemActor, protocolSystemActor);
    registry.Register(ActorIds.AppDevicePersistorActor, appDevicePersistor);
    registry.Register(ActorIds.VerificationFlowPersistorActor, verificationFlowPersistorActor);
    registry.Register(ActorIds.VerificationFlowManagerActor, verificationFlowManagerActor);
    registry.Register(ActorIds.MembershipPersistorActor, membershipPersistorActor);
    registry.Register(ActorIds.MembershipActor, membershipActor);

    logger.LogInformation("Registered top-level actors: {ProtocolActorPath}, {PersistorActorPath}",
        protocolSystemActor.Path, appDevicePersistor.Path);
}

internal class ActorSystemHostedService(ActorSystem actorSystem) : IHostedService
{
    private readonly ActorSystem _actorSystem = actorSystem;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service started - {ActorSystemName}", _actorSystem.Name);

        RegisterShutdownHooks();

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service initiating graceful shutdown...");

        try
        {
            using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMinutes(2));

            CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(_actorSystem);
            await coordinatedShutdown.Run(CoordinatedShutdown.ClrExitReason.Instance);

            Log.Information("Actor system coordinated shutdown completed successfully");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Log.Warning("Shutdown was cancelled by host, forcing actor system termination");
            await _actorSystem.Terminate();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during actor system shutdown, forcing termination");
            await _actorSystem.Terminate();
        }

        Log.Information("Actor system hosted service shutdown complete");
    }

    private void RegisterShutdownHooks()
    {
        CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(_actorSystem);

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeServiceUnbind, "stop-accepting-new-connections", () =>
        {
            Log.Information("Phase: Stop accepting new connections");
            return Task.FromResult(Done.Instance);
        });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseServiceRequestsDone, "drain-active-requests", async () =>
        {
            Log.Information("Phase: Draining active requests");

            await Task.Delay(TimeSpan.FromSeconds(5));

            Log.Information("Active request draining completed");
            return Done.Instance;
        });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeActorSystemTerminate, "cleanup-resources", () =>
        {
            Log.Information("Phase: Cleaning up application resources");

            return Task.FromResult(Done.Instance);
        });
    }
}