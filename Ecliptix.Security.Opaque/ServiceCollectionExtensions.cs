using Ecliptix.Security.Opaque.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Ecliptix.Security.Opaque;

public static class ServiceCollectionExtensions
{
    public static void AddOpaqueProtocol(this IServiceCollection services)
    {
        services.AddSingleton<INativeOpaqueProtocolService, OpaqueProtocolService>();
    }
}