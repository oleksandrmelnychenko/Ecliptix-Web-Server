using System.Globalization;
using System.IO.Compression;
using Akka.Actor;
using Akka.Hosting;
using Ecliptix.Core.Interceptors;
using Ecliptix.Core.Protocol.Actors;
using Ecliptix.Core.Resources;
using Ecliptix.Core.Services;
using Ecliptix.Core.Services.Memberships;
using Ecliptix.Domain;
using Ecliptix.Domain.AppDevices.Persistors;
using Ecliptix.Domain.DbConnectionFactory;
using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Memberships.OPAQUE;
using Ecliptix.Domain.Memberships.Persistors;
using Ecliptix.Domain.Memberships.PhoneNumberValidation;
using Ecliptix.Domain.Memberships.WorkerActors;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Serilog;
using Serilog.Context;

const string systemActorName = "EcliptixProtocolSystemActor";

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Host.UseSerilog();

try
{
    IConfiguration configuration = builder.Configuration;

    builder.Services.AddSingleton<SNSProvider>();
    builder.Services.AddSingleton<IDbConnectionFactory, DbConnectionFactory>();

    RegisterLocalization(builder.Services);
    RegisterValidators(builder.Services);
    RegisterGrpc(builder.Services);

    builder.Services.AddSingleton<ILocalizationProvider, VerificationFlowLocalizer>();
    builder.Services.AddSingleton<IPhoneNumberValidator, PhoneNumberValidator>();
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

    builder.Services.AddAkka(systemActorName, (akkaBuilder, serviceProvider) =>
    {
        akkaBuilder.WithActors((system, registry) =>
        {
            ILogger<Program> logger = serviceProvider.GetRequiredService<ILogger<Program>>();
            SNSProvider snsProvider = serviceProvider.GetRequiredService<SNSProvider>();

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

            registry.Register<EcliptixProtocolSystemActor>(protocolSystemActor);
            registry.Register<AppDevicePersistorActor>(appDevicePersistor);
            registry.Register<VerificationFlowPersistorActor>(verificationFlowPersistorActor);
            registry.Register<VerificationFlowManagerActor>(verificationFlowManagerActor);
            registry.Register<MembershipPersistorActor>(membershipPersistorActor);
            registry.Register<MembershipActor>(membershipActor);

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
    app.UseRequestLocalization();
    app.UseRouting();
    app.UseResponseCompression();
    app.UseDefaultFiles();
    app.UseStaticFiles();

    app.MapGrpcService<AppDeviceServices>();
    app.MapGrpcService<VerificationFlowServices>();
    app.MapGrpcService<MembershipServices>();

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
        options.Interceptors.Add<FailureHandlingInterceptor>();
        options.Interceptors.Add<RequestMetaDataInterceptor>();
        options.Interceptors.Add<ThreadCultureInterceptor>();
    });
}

internal class ActorSystemHostedService(ActorSystem actorSystem)
    : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service started ()");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Information("Actor system hosted service initiating shutdown...");
        await CoordinatedShutdown.Get(actorSystem).Run(CoordinatedShutdown.ClrExitReason.Instance);
        Log.Information("Actor system hosted service shutdown complete");
    }
}