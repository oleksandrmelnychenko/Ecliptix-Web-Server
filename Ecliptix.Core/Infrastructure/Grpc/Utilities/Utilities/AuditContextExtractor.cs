using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public record AuditContext(
    string? IpAddress,
    string Platform);

public static class AuditContextExtractor
{
    public static AuditContext ExtractFromContext(ServerCallContext context)
    {
        string? ipAddress = ExtractIpAddress(context);
        string platform = ExtractPlatform(context);
        return new AuditContext(ipAddress, platform);
    }

    private static string? ExtractIpAddress(ServerCallContext context)
    {
        string? metadataIp = GrpcMetadataHandler.GetLocalIpAddress(context.RequestHeaders);
        if (!string.IsNullOrEmpty(metadataIp))
        {
            return metadataIp;
        }

        string? httpContextIp = context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrEmpty(httpContextIp))
        {
            return httpContextIp;
        }

        return PlatformDetector.GetLocalIpAddress();
    }

    private static string ExtractPlatform(ServerCallContext context)
    {
        string? metadataPlatform = GrpcMetadataHandler.GetPlatform(context.RequestHeaders);
        if (!string.IsNullOrEmpty(metadataPlatform))
        {
            return metadataPlatform;
        }

        return PlatformDetector.GetPlatformInfo();
    }
}
