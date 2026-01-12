using Ecliptix.SharedKernel;
using Grpc.Core;
using Serilog;

namespace Ecliptix.SharedKernel.Grpc.Utilities;

public static class DeviceIdResolver
{
    private const string AppDeviceId = MetadataConstants.Keys.DeviceId;

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

            ClientErrorInfo clientError = new(
                descriptor.ErrorCode,
                ErrorI18NKeys.Validation,
                Retryable: false,
                ErrorSurface.User,
                PublicErrorCode: "device_id.invalid");

            throw new GrpcFailureException(
                descriptor.CreateStatus(clientError.MessageKey),
                descriptor,
                structuredLogPayload: new
                {
                    DeviceId = deviceIdStr ?? "null",
                    IpAddress = ipAddress ?? "unknown",
                    UserAgent = userAgent ?? "unknown",
                    Method = context.Method
                });
        }

        return deviceId;
    }
}
