using System.IO.Compression;
using Ecliptix.Core.Interceptors;
using Ecliptix.Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Build configuration
IConfiguration configuration = builder.Configuration
    .SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

// Configure services
RegisterLocalization(builder.Services);
RegisterValidators(builder.Services);
RegisterGrpc(builder.Services);

builder.Services.AddLogging(loggingBuilder =>
{
    loggingBuilder.AddConsole();
    loggingBuilder.AddDebug();
    loggingBuilder.AddEventSourceLogger();
});

var app = builder.Build();

// Configure request pipeline
ConfigureRequestPipeline(app);

app.Run();

// Service registration methods
static void RegisterLocalization(IServiceCollection services)
{
    services.AddLocalization();
    services.Configure<RequestLocalizationOptions>(options =>
    {
        // Uncomment and define these if needed
        // options.SetDefaultCulture(LocalizationConfigurations.DefaultCulture);
        // options.AddSupportedUICultures(LocalizationConfigurations.SupportedCultures);
        options.FallBackToParentUICultures = true;
    });
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

// Pipeline configuration methods
static void ConfigureRequestPipeline(WebApplication app)
{
    app.UseRouting();
    app.UseHttpsRedirection();
    app.UseRequestLocalization();
    app.UseDefaultFiles();
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseResponseCompression();

    ConfigureEndpoints(app);
}

static void ConfigureEndpoints(WebApplication app)
{
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapGrpcService<AppDeviceServices>();
        endpoints.MapGet("/", () => Results.Ok("Service up and running"));
    });
}