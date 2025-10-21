using Ecliptix.Utilities;
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
        Option<string> metadataIpOpt = GrpcMetadataHandler.GetLocalIpAddress(context.RequestHeaders);
        if (metadataIpOpt.HasValue)
        {
            return metadataIpOpt.Value;
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
        Option<string> metadataPlatformOpt = GrpcMetadataHandler.GetPlatform(context.RequestHeaders);
        if (metadataPlatformOpt.HasValue)
        {
            return metadataPlatformOpt.Value;
        }

        return PlatformDetector.GetPlatformInfo();
    }
}
