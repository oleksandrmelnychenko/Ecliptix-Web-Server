using Ecliptix.SharedKernel;
using Grpc.Core;

namespace Ecliptix.DeviceProvisioning.Domain.Failures;

public sealed record AppDeviceFailure(
    AppDeviceFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    private bool IsRecoverable =>
        FailureType is AppDeviceFailureType.Infrastructure;

    public override bool IsUserFacing => FailureType switch
    {
        _ => false
    };

    public override bool Retryable => FailureType switch
    {
        AppDeviceFailureType.Infrastructure => true,
        _ => false
    };

    public override ErrorSurface Surface => FailureType switch
    {
        _ => ErrorSurface.System
    };

    public override string PublicErrorCode => FailureType switch
    {
        AppDeviceFailureType.Infrastructure => "device.infrastructure",
        _ => "device.internal"
    };

    public override string? UserMessageKey => FailureType switch
    {
        AppDeviceFailureType.Infrastructure => ErrorI18NKeys.ServiceUnavailable,
        _ => ErrorI18NKeys.Internal
    };

    public static AppDeviceFailure InfrastructureFailure(string msgKey = AppDeviceMessageKeys.DataAccess,
        Exception? ex = null)
    {
        return new AppDeviceFailure(AppDeviceFailureType.Infrastructure, msgKey, ex);
    }

    public static AppDeviceFailure InternalError(string msgKey = AppDeviceMessageKeys.Generic, Exception? ex = null)
    {
        return new AppDeviceFailure(AppDeviceFailureType.Internal, msgKey, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        FailureType switch
        {
            AppDeviceFailureType.Infrastructure => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                UserMessageKey ?? ErrorI18NKeys.ServiceUnavailable,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                UserMessageKey ?? ErrorI18NKeys.Internal)
        };

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsRecoverable,
            IsUserFacing,
            Retryable,
            Surface = Surface.ToString(),
            PublicErrorCode
        };
    }
}
