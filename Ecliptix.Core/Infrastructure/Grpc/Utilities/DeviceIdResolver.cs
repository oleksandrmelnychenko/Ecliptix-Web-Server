using Ecliptix.Core.Configuration;
using Ecliptix.Utilities;
using Grpc.Core;
using Serilog;

namespace Ecliptix.Core.Infrastructure.Grpc.Utilities;

public static class DeviceIdResolver
{
    private const string AppDeviceId = MetadataConstants.Keys.AppDeviceId;

    public static Guid ResolveDeviceIdFromContext(ServerCallContext context)
    {
        string? deviceIdStr = context.RequestHeaders.GetValue(AppDeviceId);

        if (!Guid.TryParse(deviceIdStr, out Guid deviceId))
        {
            string? ipAddress = context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString();
            string? userAgent = context.RequestHeaders.GetValue("user-agent");

            Log.Warning(
                "[SECURITY] Invalid or missing device ID header. DeviceId: {DeviceId}, IP: {IpAddress}, UserAgent: {UserAgent}, Method: {Method}",
                deviceIdStr ?? "null",
                ipAddress ?? "unknown",
                userAgent ?? "unknown",
                context.Method);

            GrpcErrorDescriptor descriptor = new(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                ErrorI18NKeys.Validation);

            throw new GrpcFailureException(
                descriptor.CreateStatus("Missing or invalid d-identifier header"),
                descriptor);
        }

        return deviceId;
    }
}
