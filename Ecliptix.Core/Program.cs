using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Threading.RateLimiting;
using Akka;
using Akka.Actor;
using Akka.Configuration;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Serilog;
using Ecliptix.Core;
using Ecliptix.Core.Api.Grpc.Services.Authentication;
using Ecliptix.Core.Api.Grpc.Services.Device;
using Ecliptix.Core.Api.Grpc.Services.Membership;
using Ecliptix.Core.Configuration;
using Ecliptix.Core.Domain.Protocol.Monitoring;
using Ecliptix.Core.Infrastructure.Grpc.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware;
using Ecliptix.Core.Resources;
using Ecliptix.Core.Services;
using StackExchange.Redis;
using Ecliptix.Domain;
using Ecliptix.Domain.Abstractions;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Security.SSL.Native.Services;
using Ecliptix.Security.Opaque;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Providers.Twilio;
using static Ecliptix.Core.Configuration.NetworkConstants;
using AppConstants = Ecliptix.Core.Configuration.ApplicationConstants;
using HealthStatus = Ecliptix.Core.Json.HealthStatus;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

try
{
    ConfigureLogging(builder);
    ConfigureServices(builder);
    ConfigureActorSystem(builder);

    WebApplication app = builder.Build();

    ConfigureMiddleware(app);
    ConfigureEndpoints(app);

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

static void ConfigureLogging(WebApplicationBuilder builder)
{
    builder.Host.UseSerilog((context, services, loggerConfig) =>
    {
        string? appInsightsConnectionString =
            Environment.GetEnvironmentVariable(SecurityConstants.EnvironmentVariables
                .ApplicationInsightsConnectionString);

        loggerConfig
            .ReadFrom.Configuration(context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.WithProperty(AppConstants.Logging.Environment, context.HostingEnvironment.EnvironmentName);

        if (!string.IsNullOrEmpty(appInsightsConnectionString))
        {
            loggerConfig.WriteTo.ApplicationInsights(
                new TelemetryConfiguration { ConnectionString = appInsightsConnectionString },
                TelemetryConverter.Traces);
        }
    });
}

static void ConfigureServices(WebApplicationBuilder builder)
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

    builder.Services.Configure<TwilioSettings>(
        builder.Configuration.GetSection(AppConstants.Configuration.TwilioSettings));
    builder.Services.Configure<SecurityKeysSettings>(
        builder.Configuration.GetSection(AppConstants.Configuration.SecurityKeys));

    IConfigurationSection securityKeysSection =
        builder.Configuration.GetSection(AppConstants.Configuration.SecurityKeys);
    MetadataConstants.SecurityKeys.KeyExchangeContextTypeKey = securityKeysSection["KeyExchangeContextTypeKey"] ??
                                                               MetadataConstants.SecurityKeys.KeyExchangeContextTypeKey;
    MetadataConstants.SecurityKeys.KeyExchangeContextTypeValue = securityKeysSection["KeyExchangeContextTypeValue"] ??
                                                                 MetadataConstants.SecurityKeys
                                                                     .KeyExchangeContextTypeValue;

    builder.Services.AddSingleton<ISmsProvider>(serviceProvider =>
    {
        TwilioSettings twilioSettings = serviceProvider.GetRequiredService<IOptions<TwilioSettings>>().Value;
        return new TwilioSmsProvider(twilioSettings);
    });

    builder.Services.AddSingleton<IEcliptixActorRegistry, ActorRegistry>();
    builder.Services.AddSingleton<ILocalizationProvider, VerificationFlowLocalizer>();
    builder.Services.AddSingleton<IPhoneNumberValidator, PhoneNumberValidator>();
    builder.Services.AddSingleton<IGrpcCipherService, GrpcCipherService>();
    // Configure Redis for distributed session key caching
    string? redisConnectionString = builder.Configuration.GetConnectionString("Redis");
    if (string.IsNullOrEmpty(redisConnectionString))
        throw new InvalidOperationException("Redis connection string is required for session key management.");

    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = redisConnectionString;
        options.InstanceName = "Ecliptix";
    });

    builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
        ConnectionMultiplexer.Connect(redisConnectionString));

    builder.Services.AddDataProtection();
    builder.Services.AddSingleton<ISessionKeyService, DistributedSessionKeyService>();

    builder.Services.AddSingleton<ObjectPool<StringBuilder>>(_ =>
    {
        DefaultObjectPoolProvider provider = new();
        return provider.CreateStringBuilderPool();
    });

    builder.Services.AddOpaqueProtocol();
    builder.Services.AddSingleton<ServerSecurityService>();

    builder.Services.AddHealthChecks()
        .AddCheck<ProtocolHealthCheck>(AppConstants.HealthChecks.ProtocolHealth)
        .AddCheck<VerificationFlowHealthCheck>(AppConstants.HealthChecks.VerificationFlowHealth)
        .AddCheck<DatabaseHealthCheck>(AppConstants.HealthChecks.DatabaseHealth);

    builder.Services.AddHostedService<ServerSecurityInitializationService>();
    builder.Services.AddHostedService<ActorSystemInitializationService>();
}

static void ConfigureActorSystem(WebApplicationBuilder builder)
{
    const string systemActorName = AppConstants.ActorSystem.SystemName;
    Config akkaConfig = ConfigurationFactory.Empty
        .WithFallback(ConfigurationFactory.ParseString(File.ReadAllText(AppConstants.ActorSystem.ConfigFileName)));
    ActorSystem actorSystem = ActorSystem.Create(systemActorName, akkaConfig);

    builder.Services.AddSingleton(actorSystem);
    builder.Services.AddHostedService<ActorSystemHostedService>();
}

static void ConfigureMiddleware(WebApplication app)
{
    app.UseSerilogRequestLogging(options =>
    {
        options.MessageTemplate = AppConstants.Logging.HttpRequestTemplate;
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
}

static void ConfigureEndpoints(WebApplication app)
{
    app.MapGrpcService<DeviceGrpcService>();
    app.MapGrpcService<VerificationFlowServices>();
    app.MapGrpcService<MembershipServices>();

    app.MapHealthChecks(AppConstants.Endpoints.Health);

    app.MapGet(AppConstants.Endpoints.Metrics, async (IServiceProvider services) =>
    {
        try
        {
            ActorSystem actorSystem = services.GetRequiredService<ActorSystem>();
            IOpaqueProtocolService opaqueProtocolService = services.GetRequiredService<IOpaqueProtocolService>();
            byte[] t = opaqueProtocolService.GetPublicKey();
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

    app.MapGet(AppConstants.Endpoints.Root,
        () => Results.Ok(new { Status = "Success", Message = "Server is up and running" }));
}

static void RegisterLocalization(IServiceCollection services)
{
    services.AddLocalization(options => options.ResourcesPath = AppConstants.Localization.ResourcesPath);
    services.Configure<RequestLocalizationOptions>(options =>
    {
        CultureInfo[] supported =
            [new(AppConstants.Localization.DefaultCulture), new(AppConstants.Localization.UkrainianCulture)];
        options.DefaultRequestCulture = new RequestCulture(AppConstants.Localization.DefaultCulture);
        options.SupportedUICultures = supported;
        options.SupportedCultures = supported;
        options.SetDefaultCulture(AppConstants.Localization.DefaultCulture);
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
                    PermitLimit = RateLimit.PermitLimit,
                    Window = TimeSpan.FromMinutes(RateLimit.WindowMinutes),
                    SegmentsPerWindow = RateLimit.SegmentsPerWindow,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = RateLimit.QueueLimit
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
        options.Limits.MaxRequestBodySize = Limits.MaxRequestBodySizeBytes;
        options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(Timeouts.RequestHeadersTimeoutSeconds);
        options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(Timeouts.KeepAliveTimeoutMinutes);
        options.Limits.MaxConcurrentConnections = Limits.MaxConcurrentConnections;
        options.Limits.MaxConcurrentUpgradedConnections = Limits.MaxConcurrentUpgradedConnections;
    });

    services.AddDistributedMemoryCache();
    services.AddMemoryCache();
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
        options.ResponseCompressionAlgorithm = Compression.Algorithm;
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
        options.ListenAnyIP(Ports.Grpc, listenOptions => { listenOptions.Protocols = HttpProtocols.Http2; });

        options.ListenAnyIP(Ports.Http, listenOptions => { listenOptions.Protocols = HttpProtocols.Http1; });
    });
}


internal class ActorSystemHostedService(ActorSystem actorSystem) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service started - {ActorSystemName}", actorSystem.Name);

        RegisterShutdownHooks();

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service initiating graceful shutdown...");

        try
        {
            using CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMinutes(Timeouts.ShutdownGracefulTimeoutMinutes));

            CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);
            await coordinatedShutdown.Run(CoordinatedShutdown.ClrExitReason.Instance);

            Log.Information("Actor system coordinated shutdown completed successfully");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Log.Warning("Shutdown was cancelled by host, forcing actor system termination");
            await actorSystem.Terminate();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during actor system shutdown, forcing termination");
            await actorSystem.Terminate();
        }

        Log.Information("Actor system hosted service shutdown complete");
    }

    private void RegisterShutdownHooks()
    {
        CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeServiceUnbind, "stop-accepting-new-connections",
            () =>
            {
                Log.Information("Phase: Stop accepting new connections");
                return Task.FromResult(Done.Instance);
            });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseServiceRequestsDone, "drain-active-requests", async () =>
        {
            Log.Information("Phase: Draining active requests");

            await Task.Delay(TimeSpan.FromSeconds(Timeouts.DrainActiveRequestsSeconds));

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