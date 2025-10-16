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

    public override Grpc.Core.Status ToGrpcStatus()
    {
        StatusCode code = FailureType switch
        {
            AppDeviceFailureType.InfrastructureFailure => StatusCode.Unavailable,
            AppDeviceFailureType.InternalError => StatusCode.Internal,
            _ => StatusCode.Unknown
        };

        return new Grpc.Core.Status(code, Message);
    }

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