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
using Ecliptix.Core.Infrastructure.Crypto;
using Ecliptix.Core.Infrastructure.Grpc.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Infrastructure.SecureChannel;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware;
using Ecliptix.Core.Resources;
using Ecliptix.Core.Services;
using StackExchange.Redis;
using Ecliptix.Domain;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Providers.Twilio;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Services;
using Ecliptix.Utilities;
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

    InitializeOpaqueService(app);

    ConfigureMiddleware(app);
    ConfigureEndpoints(app);

    Log.Information(AppConstants.LogMessages.StartingApplication);
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, AppConstants.LogMessages.ApplicationTerminatedUnexpectedly);
    throw;
}
finally
{
    Log.Information(AppConstants.LogMessages.ShuttingDownApplication);
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
    MetadataConstants.SecurityKeys.KeyExchangeContextTypeKey =
        securityKeysSection[AppConstants.ConfigurationKeys.KeyExchangeContextTypeKey] ??
        MetadataConstants.SecurityKeys.KeyExchangeContextTypeKey;
    MetadataConstants.SecurityKeys.KeyExchangeContextTypeValue =
        securityKeysSection[AppConstants.ConfigurationKeys.KeyExchangeContextTypeValue] ??
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
    string? redisConnectionString = builder.Configuration.GetConnectionString(AppConstants.Redis.ConnectionStringKey);
    if (string.IsNullOrEmpty(redisConnectionString))
        throw new InvalidOperationException(AppConstants.Redis.RequiredConnectionStringMessage);

    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = redisConnectionString;
        options.InstanceName = AppConstants.Redis.InstanceName;
    });

    builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
        ConnectionMultiplexer.Connect(redisConnectionString));

    builder.Services.AddDataProtection();

    builder.Services.AddSingleton<ObjectPool<StringBuilder>>(_ =>
    {
        DefaultObjectPoolProvider provider = new();
        return provider.CreateStringBuilderPool();
    });

    builder.Services.AddOpaqueProtocol();

    builder.Services.AddSingleton<IOpaqueProtocolService>(serviceProvider =>
    {
        INativeOpaqueProtocolService nativeService = serviceProvider.GetRequiredService<INativeOpaqueProtocolService>();
        return new OpaqueProtocolAdapter(nativeService);
    });

    builder.Services.AddSingleton<CertificatePinningService>();

    builder.Services.AddSingleton<IRsaConfiguration, RsaConfiguration>();
    builder.Services.AddSingleton<IRsaChunkProcessor, RsaChunkProcessor>();
    builder.Services.AddSingleton<ISecureChannelEstablisher>(serviceProvider =>
    {
        IRsaChunkProcessor rsaChunkProcessor = serviceProvider.GetRequiredService<IRsaChunkProcessor>();
        CertificatePinningService certificatePinningService = serviceProvider.GetRequiredService<CertificatePinningService>();
        IEcliptixActorRegistry actorRegistry = serviceProvider.GetRequiredService<IEcliptixActorRegistry>();
        IActorRef protocolActor = actorRegistry.Get(ActorIds.EcliptixProtocolSystemActor);

        return new RsaSecureChannelEstablisher(rsaChunkProcessor, certificatePinningService, protocolActor);
    });

    builder.Services.AddHealthChecks()
        .AddCheck<ProtocolHealthCheck>(AppConstants.HealthChecks.ProtocolHealth)
        .AddCheck<VerificationFlowHealthCheck>(AppConstants.HealthChecks.VerificationFlowHealth)
        .AddCheck<DatabaseHealthCheck>(AppConstants.HealthChecks.DatabaseHealth);

    builder.Services.AddHostedService<CertificatePinningServiceHost>();
    builder.Services.AddHostedService<ActorSystemInitializationHost>();
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
            diagnosticContext.Set(AppConstants.DiagnosticContext.RequestHost, httpContext.Request.Host.Value!);
            diagnosticContext.Set(AppConstants.DiagnosticContext.UserAgent,
                httpContext.Request.Headers[AppConstants.HttpHeaders.UserAgent].ToString());
            diagnosticContext.Set(AppConstants.DiagnosticContext.Protocol, httpContext.Request.Protocol);

            if (httpContext.Request.Headers.TryGetValue(AppConstants.HttpHeaders.ConnectId, out StringValues connectId))
            {
                diagnosticContext.Set(AppConstants.DiagnosticContext.ConnectId, connectId.ToString());
            }

            if (httpContext.Request.ContentLength.HasValue)
            {
                diagnosticContext.Set(AppConstants.DiagnosticContext.RequestSize,
                    httpContext.Request.ContentLength.Value);
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
    app.MapGrpcService<DeviceService>();
    app.MapGrpcService<VerificationFlowServices>();
    app.MapGrpcService<MembershipServices>();

    app.MapHealthChecks(AppConstants.Endpoints.Health);

    app.MapGet(AppConstants.Endpoints.Metrics, async (IServiceProvider services) =>
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
                    AppConstants.StatusMessages.Available,
                    AppConstants.StatusMessages.ProtocolMetricsActive,
                    AppConstants.StatusMessages.FullMetricsAvailable
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
        () => Results.Ok(new
            { Status = AppConstants.StatusMessages.Success, Message = AppConstants.StatusMessages.ServerRunning }));
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
                partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ??
                              AppConstants.FallbackValues.UnknownIpAddress,
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
            Log.Warning(AppConstants.LogMessages.RateLimitExceeded,
                context.HttpContext.Connection.RemoteIpAddress?.ToString() ??
                AppConstants.FallbackValues.UnknownIpAddress);
            return ValueTask.CompletedTask;
        };
    });

    services.AddSingleton<CertificatePinningService>();

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

static void InitializeOpaqueService(WebApplication app)
{
    INativeOpaqueProtocolService opaqueService = app.Services.GetRequiredService<INativeOpaqueProtocolService>();
    SecurityKeysSettings securityKeysSettings = app.Services.GetRequiredService<IOptions<SecurityKeysSettings>>().Value;
    Result<Unit, OpaqueServerFailure> initializationResult =
        opaqueService.Initialize(securityKeysSettings.OpaqueSecretKeySeed);
    if (!initializationResult.IsErr) return;
    string errorMessage = initializationResult.UnwrapErr().Message;
    Log.Error(errorMessage);
}

internal class ActorSystemHostedService(ActorSystem actorSystem) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Log.Information(AppConstants.LogMessages.ActorSystemStarted, actorSystem.Name);

        RegisterShutdownHooks();

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Information(AppConstants.LogMessages.ActorSystemInitiatingShutdown);

        try
        {
            using CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMinutes(Timeouts.ShutdownGracefulTimeoutMinutes));

            CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);
            await coordinatedShutdown.Run(CoordinatedShutdown.ClrExitReason.Instance);

            Log.Information(AppConstants.LogMessages.ActorSystemShutdownCompleted);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Log.Warning(AppConstants.LogMessages.ShutdownCancelledForcing);
            await actorSystem.Terminate();
        }
        catch (Exception ex)
        {
            Log.Error(ex, AppConstants.LogMessages.ErrorDuringShutdownForcing);
            await actorSystem.Terminate();
        }

        Log.Information(AppConstants.LogMessages.ActorSystemShutdownComplete);
    }

    private void RegisterShutdownHooks()
    {
        CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeServiceUnbind,
            AppConstants.ActorSystemTasks.StopAcceptingNewConnections,
            () =>
            {
                Log.Information(AppConstants.LogMessages.PhaseStopAcceptingConnections);
                return Task.FromResult(Done.Instance);
            });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseServiceRequestsDone,
            AppConstants.ActorSystemTasks.DrainActiveRequests, async () =>
            {
                Log.Information(AppConstants.LogMessages.PhaseDrainingActiveRequests);

                await Task.Delay(TimeSpan.FromSeconds(Timeouts.DrainActiveRequestsSeconds));

                Log.Information(AppConstants.LogMessages.ActiveRequestDrainingCompleted);
                return Done.Instance;
            });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeActorSystemTerminate,
            AppConstants.ActorSystemTasks.CleanupResources, () =>
            {
                Log.Information(AppConstants.LogMessages.PhaseCleanupResources);

                return Task.FromResult(Done.Instance);
            });
    }
}