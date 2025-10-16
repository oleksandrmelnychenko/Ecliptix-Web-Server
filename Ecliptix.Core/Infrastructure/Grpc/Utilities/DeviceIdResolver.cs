using Grpc.Core;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities;

public static class DeviceIdResolver
{
    private const string AppDeviceId = "d-identifier";

    /// <summary>
    /// Resolves and validates the device identifier from the gRPC request headers.
    /// </summary>
    /// <param name="context">The gRPC server call context containing request headers.</param>
    /// <returns>The validated device ID as a GUID.</returns>
    /// <exception cref="RpcException">Thrown when the device ID header is missing or invalid.</exception>
    public static Guid ResolveDeviceIdFromContext(ServerCallContext context)
    {
        string? deviceIdStr = context.RequestHeaders.GetValue(AppDeviceId);

        if (!Guid.TryParse(deviceIdStr, out Guid deviceId))
        {
            // Log security event for invalid/missing device ID attempts
            string? ipAddress = context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString();
            string? userAgent = context.RequestHeaders.GetValue("user-agent");

            Log.Warning(
                "[SECURITY] Invalid or missing device ID header. DeviceId: {DeviceId}, IP: {IpAddress}, UserAgent: {UserAgent}, Method: {Method}",
                deviceIdStr ?? "null",
                ipAddress ?? "unknown",
                userAgent ?? "unknown",
                context.Method);

            throw new RpcException(new Status(StatusCode.InvalidArgument, "Missing or invalid d-identifier header"));
        }

        return deviceId;
    }
}
