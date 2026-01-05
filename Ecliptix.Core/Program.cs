using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Threading.RateLimiting;
using Akka;
using Akka.Actor;
using Ecliptix.Core;
using Ecliptix.Core.Api.Grpc.Services.Transport;
using Ecliptix.Core.Configuration;
using Ecliptix.Core.Configuration.Settings;
using Ecliptix.Core.Infrastructure.Grpc.Interceptors;
using Ecliptix.Core.Infrastructure.Grpc.Routing;
using Ecliptix.Core.Infrastructure.Grpc.Routing.Handlers;
using Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities.CipherPayloadHandler;
using Ecliptix.Core.Json;
using Ecliptix.Core.Middleware;
using Ecliptix.Core.Resources;
using Ecliptix.Core.Services;
using Ecliptix.IdentityAccess.Domain;
using Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;
using Ecliptix.IdentityAccess.Domain.Providers.Twilio;
using Ecliptix.IdentityAccess.Domain.Schema;
using Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;
using Ecliptix.Protobuf.Account;
using Ecliptix.Security.Certificate.Pinning.Services;
using Ecliptix.Security.Opaque;
using Ecliptix.Security.Opaque.Contracts;
using Ecliptix.Security.Opaque.Failures;
using Ecliptix.Security.Opaque.Services;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Grpc.Utilities;
using Ecliptix.SharedKernel.Grpc.Utilities.CipherPayloadHandler;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.DeviceProvisioning.Infrastructure.Crypto;
using Ecliptix.DeviceProvisioning.Infrastructure.SecureChannel;
using DP = Ecliptix.DeviceProvisioning.Infrastructure.Grpc;
using IA = Ecliptix.IdentityAccess.Infrastructure.Grpc;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using AppConstants = Ecliptix.Core.Configuration.ApplicationConstants;
using HealthStatus = Ecliptix.Core.Json.HealthStatus;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

try
{
    ConfigureLogging(builder);
    ConfigureServices(builder);
    ConfigureOpenTelemetry(builder);
    AkkaConfiguration.ConfigureAkka(builder);

    WebApplication app = builder.Build();

    bool migrateOnly = Environment.GetEnvironmentVariable(EnvironmentVariableNames.MigrateOnly) == "true";

    if (migrateOnly)
    {
        using IServiceScope scope = app.Services.CreateScope();
        EcliptixSchemaContext db = scope.ServiceProvider.GetRequiredService<EcliptixSchemaContext>();
        db.Database.Migrate();
        return;
    }

    InitializeOpaqueService(app);

    ConfigureMiddleware(app);
    ConfigureEndpoints(app);
    app.Run();
}
finally
{
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
            .Enrich.WithProperty(AppConstants.Logging.Environment, context.HostingEnvironment.EnvironmentName)
            .Filter.ByExcluding(logEvent =>
            {
                if (logEvent.Exception is NullReferenceException nullRefEx)
                {
                    string? stackTrace = nullRefEx.StackTrace;
                    if (!string.IsNullOrEmpty(stackTrace) &&
                        stackTrace.Contains("Akka.Persistence.Eventsourced.AroundPostStop"))
                    {
                        return true;
                    }
                }
                return false;
            });

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

    bool usePostgreSQL = builder.Configuration.GetValue("UsePostgreSQL", defaultValue: false);
    string? connectionString = builder.Configuration.GetConnectionString("EcliptixMemberships");
    int commandTimeout = (int)TimeoutConfiguration.Database.CommandTimeout.TotalSeconds;
    bool isDevelopment = builder.Environment.IsDevelopment();

    builder.Services.AddPooledDbContextFactory<EcliptixSchemaContext>(options =>
    {
        if (usePostgreSQL)
        {

            options.UseNpgsql(connectionString, npgsqlOptions =>
                   {
                       npgsqlOptions.CommandTimeout(commandTimeout == int.MaxValue ? 0 : commandTimeout);

                       npgsqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);

                       npgsqlOptions.UseRelationalNulls(false);
                   })
                   .UseSnakeCaseNamingConvention()
                   .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
                   .EnableSensitiveDataLogging(isDevelopment)
                   .EnableDetailedErrors(isDevelopment)
                   .AddInterceptors(new Ecliptix.IdentityAccess.Domain.Schema.Interceptors.AuditInterceptor())
                   .ConfigureWarnings(warnings =>
                       warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.PendingModelChangesWarning));
        }
        else
        {

            options.UseSqlServer(connectionString, sqlOptions =>
                   {
                       sqlOptions.CommandTimeout(commandTimeout == int.MaxValue ? 0 : commandTimeout);

                       sqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);

                       sqlOptions.UseRelationalNulls(false);
                   })
                   .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
                   .EnableSensitiveDataLogging(false)
                   .EnableDetailedErrors(false)
                   .AddInterceptors(new Ecliptix.IdentityAccess.Domain.Schema.Interceptors.AuditInterceptor())
                   .ConfigureWarnings(warnings =>
                       warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.PendingModelChangesWarning));
        }
    }, poolSize: 128);

    builder.Services.AddDbContextFactory<EcliptixSchemaContext>(options =>
    {
        if (usePostgreSQL)
        {
            options.UseNpgsql(connectionString, npgsqlOptions =>
                   {
                       npgsqlOptions.CommandTimeout(commandTimeout == int.MaxValue ? 0 : commandTimeout);
                   })
                   .UseSnakeCaseNamingConvention()
                   .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
                   .AddInterceptors(new Ecliptix.IdentityAccess.Domain.Schema.Interceptors.AuditInterceptor())
                   .ConfigureWarnings(warnings =>
                       warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.PendingModelChangesWarning));
        }
        else
        {
            options.UseSqlServer(connectionString, sqlOptions =>
                   {
                       sqlOptions.CommandTimeout(commandTimeout == int.MaxValue ? 0 : commandTimeout);
                   })
                   .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
                   .AddInterceptors(new Ecliptix.IdentityAccess.Domain.Schema.Interceptors.AuditInterceptor())
                   .ConfigureWarnings(warnings =>
                       warnings.Ignore(Microsoft.EntityFrameworkCore.Diagnostics.RelationalEventId.PendingModelChangesWarning));
        }
    });

    builder.Services.AddSingleton<SecrecyHandshakeKeepAliveInterceptor>();
    builder.Services.AddSingleton<TelemetryInterceptor>();
    builder.Services.AddSingleton<FailureHandlingInterceptor>();
    builder.Services.AddSingleton<RequestMetaDataInterceptor>();
    builder.Services.AddSingleton<ThreadCultureInterceptor>();
    builder.Services.AddSingleton<IEventRouteResolver, EventRouteResolver>();
    builder.Services.AddSingleton<IEventRouteProvider, IdentityAccessEventRouteProvider>();
    builder.Services.AddSingleton<IEventRouteProvider, DeviceProvisioningEventRouteProvider>();
    builder.Services.AddSingleton<EventEnvelopeDispatcher>();
    builder.Services.AddSingleton<IEventHandler<Ecliptix.Protobuf.Common.SecureEnvelope>, IdentityAccessSecureEnvelopeHandler>();
    builder.Services.AddSingleton<IEventHandler<Ecliptix.Protobuf.Common.SecureEnvelope>, DeviceProvisioningSecureEnvelopeHandler>();
    builder.Services.AddSingleton<IEventHandler<Ecliptix.Protobuf.Device.AuthenticatedEstablishRequest>, DeviceProvisioningAuthenticatedEstablishHandler>();
    builder.Services.AddTransient<IA.MembershipServices>();
    builder.Services.AddTransient<IA.VerificationFlowServices>();
    builder.Services.AddTransient<IA.AccountProfileServices>();
    builder.Services.AddTransient<DP.DeviceService>();
    builder.Services.AddTransient<IdentityAccessEventsService>();
    builder.Services.AddTransient<DeviceProvisioningEventsService>();

    NetworkConfiguration networkConfig = new();
    builder.Configuration.GetSection(NetworkConfiguration.SectionName).Bind(networkConfig);

    RegisterSecurity(builder.Services, networkConfig);
    RegisterLocalization(builder.Services);
    RegisterValidators(builder.Services);
    RegisterGrpc(builder.Services, networkConfig);

    builder.Services.Configure<TwilioSettings>(
        builder.Configuration.GetSection(AppConstants.Configuration.TwilioSettings));
    builder.Services.Configure<SecurityKeysSettings>(
        builder.Configuration.GetSection(AppConstants.Configuration.SecurityKeys));
    builder.Services.Configure<SecurityConfiguration>(
        builder.Configuration.GetSection(SecurityConfiguration.SectionName));
    builder.Services.AddSingleton<IValidateOptions<SecurityConfiguration>, SecurityConfigurationValidator>();
    builder.Services.Configure<NetworkConfiguration>(
        builder.Configuration.GetSection(NetworkConfiguration.SectionName));

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
    builder.Services.AddSingleton<IMobileNumberValidator, MobileNumberValidator>();
    builder.Services.AddSingleton<IGrpcCipherService, GrpcCipherService>();

    builder.Services.AddDistributedMemoryCache();

    builder.Services.AddDataProtection();

    builder.Services.AddSingleton<ObjectPool<StringBuilder>>(_ =>
    {
        DefaultObjectPoolProvider provider = new();
        return provider.CreateStringBuilderPool();
    });

    builder.Services.AddOpaqueProtocol();

    builder.Services.AddSingleton<IOpaqueProtocolService>(serviceProvider =>
    {
        IOpaqueKeyRingService keyRingService = serviceProvider.GetRequiredService<IOpaqueKeyRingService>();
        return new OpaqueProtocolAdapter(keyRingService);
    });

    builder.Services.AddSingleton<CertificatePinningService>();

    builder.Services.AddSingleton<Ecliptix.Core.Services.KeyDerivation.IHardenedKeyDerivation, Ecliptix.Core.Services.KeyDerivation.HardenedKeyDerivation>();
    builder.Services.AddSingleton<Ecliptix.Core.Services.KeyDerivation.ISecretSharingService, Ecliptix.Core.Services.KeyDerivation.ShamirSecretSharing>();
    builder.Services.AddSingleton<Ecliptix.Core.Services.KeyDerivation.IIdentityKeyDerivationService, Ecliptix.Core.Services.KeyDerivation.IdentityKeyDerivationService>();
    builder.Services.AddSingleton<Ecliptix.IdentityAccess.Domain.Services.Security.IMasterKeyService, Ecliptix.Core.Services.Security.MasterKeyService>();

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

    builder.Services.AddHealthChecks();

    builder.Services.AddHostedService<CertificatePinningServiceHost>();
    builder.Services.AddHostedService<ActorSystemInitializationHost>();
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
                httpContext.Request.Headers[SecurityConstants.HttpHeaders.UserAgent].ToString());
            diagnosticContext.Set(AppConstants.DiagnosticContext.Protocol, httpContext.Request.Protocol);

            if (httpContext.Request.Headers.TryGetValue(SecurityConstants.HttpHeaders.XConnectId, out StringValues connectId))
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
    app.UseRequestLocalization();
    app.UseRouting();
    app.UseResponseCompression();
    app.UseDefaultFiles();
    app.UseStaticFiles();
}

static void ConfigureEndpoints(WebApplication app)
{
    app.MapGrpcService<DP.DeviceService>();
    app.MapGrpcService<IA.VerificationFlowServices>();
    app.MapGrpcService<IA.MembershipServices>();
    app.MapGrpcService<IA.AccountProfileServices>();
    app.MapGrpcService<IdentityAccessEventsService>();
    app.MapGrpcService<DeviceProvisioningEventsService>();

    app.MapHealthChecks(AppConstants.Endpoints.Health);

    app.MapGet(AppConstants.Endpoints.Metrics, () =>
    {
        HealthMetricsResponse response = new(
            new HealthStatus(
                "Healthy",
                "Metrics endpoint available",
                null
            ),
            DateTime.UtcNow
        );

        return Results.Json(response, AppJsonSerializerContext.Default.HealthMetricsResponse);
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

static void RegisterSecurity(IServiceCollection services, NetworkConfiguration networkConfig)
{
    services.AddRateLimiter(options =>
    {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            RateLimitPartition.GetSlidingWindowLimiter(
                partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ??
                              AppConstants.FallbackValues.UnknownIpAddress,
                factory: _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = networkConfig.RateLimit.PermitLimit,
                    Window = TimeSpan.FromMinutes(networkConfig.RateLimit.WindowMinutes),
                    SegmentsPerWindow = networkConfig.RateLimit.SegmentsPerWindow,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = networkConfig.RateLimit.QueueLimit
                }));

        options.OnRejected = (context, _) =>
        {
            context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

            return ValueTask.CompletedTask;
        };
    });

    services.AddSingleton<CertificatePinningService>();

    services.Configure<KestrelServerOptions>(options =>
    {
        options.Limits.MaxRequestBodySize = networkConfig.Limits.MaxRequestBodySizeBytes;
        options.Limits.RequestHeadersTimeout = TimeoutConfiguration.Network.RequestHeadersTimeout;
        options.Limits.KeepAliveTimeout = TimeoutConfiguration.Network.KeepAliveTimeout;
        options.Limits.MaxConcurrentConnections = networkConfig.Limits.MaxConcurrentConnections;
        options.Limits.MaxConcurrentUpgradedConnections = networkConfig.Limits.MaxConcurrentUpgradedConnections;
    });

    services.AddDistributedMemoryCache();
    services.AddMemoryCache();
    services.AddHealthChecks();
}

static void RegisterValidators(IServiceCollection services)
{
    services.AddResponseCompression();
}

static void RegisterGrpc(IServiceCollection services, NetworkConfiguration networkConfig)
{
    services.AddGrpc(options =>
    {
        options.ResponseCompressionLevel = CompressionLevel.Fastest;
        options.ResponseCompressionAlgorithm = networkConfig.Compression.Algorithm;
        options.EnableDetailedErrors = true;
        options.Interceptors.Add<FailureHandlingInterceptor>();
        options.Interceptors.Add<RequestMetaDataInterceptor>();
        options.Interceptors.Add<SecrecyHandshakeKeepAliveInterceptor>();
        options.Interceptors.Add<TelemetryInterceptor>();
        options.Interceptors.Add<ThreadCultureInterceptor>();
    });

    services.Configure<KestrelServerOptions>(options =>
    {
        options.ListenAnyIP(networkConfig.Ports.Grpc, listenOptions => { listenOptions.Protocols = HttpProtocols.Http2; });
        options.ListenAnyIP(networkConfig.Ports.Http, listenOptions => { listenOptions.Protocols = HttpProtocols.Http1; });
    });
}

static void ConfigureOpenTelemetry(WebApplicationBuilder builder)
{
    string serviceName = "Ecliptix.Core";
    string serviceVersion = "1.0.0";

    builder.Services.AddOpenTelemetry()
        .ConfigureResource(resource => resource
            .AddService(
                serviceName: serviceName,
                serviceVersion: serviceVersion,
                serviceInstanceId: Environment.MachineName))
        .WithTracing(tracing =>
        {
            tracing
                .AddSource("Ecliptix.GrpcInterceptors")
                .AddSource("Ecliptix.GrpcServices")
                .AddAspNetCoreInstrumentation(options =>
                {
                    options.RecordException = true;
                    options.Filter = httpContext =>
                    {
                        string? path = httpContext.Request.Path.Value;
                        if (string.IsNullOrEmpty(path))
                        {
                            return true;
                        }

                        return !path.Contains("/health") && path != "/";
                    };
                });

            string? otlpEndpoint = Environment.GetEnvironmentVariable(EnvironmentVariableNames.OtelExporterOtlpEndpoint);
            string? consoleExporter = Environment.GetEnvironmentVariable(EnvironmentVariableNames.OtelConsoleExporterEnabled);

            if (!string.IsNullOrEmpty(otlpEndpoint))
            {
                tracing.AddOtlpExporter(otlpOptions =>
                {
                    otlpOptions.Endpoint = new Uri(otlpEndpoint);
                });
            }
            else if (string.Equals(consoleExporter, "true", StringComparison.OrdinalIgnoreCase))
            {
                tracing.AddConsoleExporter();
            }
        });
}

static void InitializeOpaqueService(WebApplication app)
{
    IOpaqueKeyRingService opaqueService = app.Services.GetRequiredService<IOpaqueKeyRingService>();
    SecurityKeysSettings securityKeysSettings = app.Services.GetRequiredService<IOptions<SecurityKeysSettings>>().Value;
    Dictionary<int, string> keyRing = securityKeysSettings.OpaqueKeyRing ?? new Dictionary<int, string>();
    int activeKeyVersion = securityKeysSettings.OpaqueActiveKeyVersion;

    if (keyRing.Count == 0)
    {
        if (string.IsNullOrWhiteSpace(securityKeysSettings.OpaqueSecretKeySeed))
        {
            Log.Error("OPAQUE key ring is empty and OpaqueSecretKeySeed is missing");
            throw new InvalidOperationException("OPAQUE key ring is empty");
        }

        keyRing = new Dictionary<int, string>
        {
            { 1, securityKeysSettings.OpaqueSecretKeySeed }
        };
        activeKeyVersion = 1;
    }

    Result<Unit, OpaqueServerFailure> initializationResult =
        opaqueService.Initialize(keyRing, activeKeyVersion);
    if (!initializationResult.IsErr)
    {
        return;
    }

    OpaqueServerFailure failure = initializationResult.UnwrapErr();
    Log.Error("OPAQUE server initialization failed: {Error}", failure.Message);
    throw new InvalidOperationException(failure.Message, failure.Exception);

}

internal class ActorSystemHostedService(ActorSystem actorSystem) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {

        RegisterShutdownHooks();

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            using CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeoutConfiguration.Network.ShutdownGracefulTimeout);

            CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);
            await coordinatedShutdown.Run(CoordinatedShutdown.ClrExitReason.Instance);
        }
        catch (OperationCanceledException ex) when (cancellationToken.IsCancellationRequested)
        {
            Log.Debug(ex, "Actor system shutdown cancelled, forcing termination");
            await actorSystem.Terminate();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during actor system shutdown, forcing termination");
            await actorSystem.Terminate();
        }
    }

    private void RegisterShutdownHooks()
    {
        CoordinatedShutdown coordinatedShutdown = CoordinatedShutdown.Get(actorSystem);

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeServiceUnbind,
            AppConstants.ActorSystemTasks.StopAcceptingNewConnections,
            () => Task.FromResult(Done.Instance));

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseServiceRequestsDone,
            AppConstants.ActorSystemTasks.DrainActiveRequests, async () =>
            {

                await Task.Delay(TimeoutConfiguration.Network.DrainActiveRequests);

                return Done.Instance;
            });

        coordinatedShutdown.AddTask(CoordinatedShutdown.PhaseBeforeActorSystemTerminate,
            AppConstants.ActorSystemTasks.CleanupResources, () => Task.FromResult(Done.Instance));
    }
}
