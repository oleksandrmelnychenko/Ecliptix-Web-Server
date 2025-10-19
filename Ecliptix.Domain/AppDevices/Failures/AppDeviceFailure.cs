using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.AppDevices.Failures;

public sealed record AppDeviceFailure(
    AppDeviceFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    private bool IsRecoverable =>
        FailureType is AppDeviceFailureType.InfrastructureFailure;

    public static AppDeviceFailure InfrastructureFailure(string msgKey = AppDeviceMessageKeys.DataAccess,
        Exception? ex = null)
    {
        return new AppDeviceFailure(AppDeviceFailureType.InfrastructureFailure, msgKey, ex);
    }

    public static AppDeviceFailure InternalError(string msgKey = AppDeviceMessageKeys.Generic, Exception? ex = null)
    {
        return new AppDeviceFailure(AppDeviceFailureType.InternalError, msgKey, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor() =>
        FailureType switch
        {
            AppDeviceFailureType.InfrastructureFailure => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                ErrorI18nKeys.ServiceUnavailable,
                Retryable: true),
            AppDeviceFailureType.InternalError => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18nKeys.Internal),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                ErrorI18nKeys.Internal)
        };

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsRecoverable
        };
    }
}
