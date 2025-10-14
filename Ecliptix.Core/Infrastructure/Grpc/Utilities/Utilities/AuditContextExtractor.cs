using Grpc.Core;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities.Utilities;

public record AuditContext(
    string? IpAddress,
    string Platform);

public static class AuditContextExtractor
{
    private const string PlatformKey = "platform";

    public static AuditContext ExtractFromContext(ServerCallContext context)
    {
        string? ipAddress = context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString();
        string platform = context.RequestHeaders.GetValue(PlatformKey) ?? "Unknown";
        return new AuditContext(ipAddress, platform);
    }
}
