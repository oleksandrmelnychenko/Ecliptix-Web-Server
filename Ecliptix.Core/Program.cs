using System.IO.Compression;
using Ecliptix.Core.Interceptors;
using Ecliptix.Core.Services;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using OpenTelemetry.Metrics;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

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

// Add OpenTelemetry with console exporter for testing
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddAspNetCoreInstrumentation();
        metrics.AddConsoleExporter(); // For debugging; replace with OTLP in production
    });

// Configure Kestrel for HTTP/3
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5001, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http3 | HttpProtocols.Http2; // Support HTTP/3 and HTTP/2
        // Note: Requires TLS certificate in production
    });
});

var app = builder.Build();

// Configure request pipeline
app.UseRateLimiter(); // Early to limit all requests
app.UseHttpsRedirection();
app.UseRequestLocalization();
app.UseDefaultFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseResponseCompression();

// Top-level route registrations
app.MapGrpcService<AppDeviceServices>();
app.MapGet("/", () => Results.Ok("Service up and running"));
app.MapHealthChecks("/health"); // Optional: Expose health endpoint

app.Run();

// Service registration methods
static void RegisterLocalization(IServiceCollection services)
{
    services.AddLocalization();
    services.Configure<RequestLocalizationOptions>(options =>
    {
        options.FallBackToParentUICultures = true;
        // Uncomment if needed:
        // options.SetDefaultCulture(LocalizationConfigurations.DefaultCulture);
        // options.AddSupportedUICultures(LocalizationConfigurations.SupportedCultures);
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