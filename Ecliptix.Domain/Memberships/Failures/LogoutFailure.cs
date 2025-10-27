using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record LogoutFailure(
    LogoutFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        LogoutFailureType.PersistorAccess => true,
        LogoutFailureType.QueryFailed => true,
        _ => false
    };

    public static LogoutFailure RecordFailed(string? details = null, Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.RecordFailed,
            details ?? LogoutMessageKeys.AuditRecordFailed, ex);
    }

    public static LogoutFailure QueryFailed(string? details = null, Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.QueryFailed,
            details ?? LogoutMessageKeys.QueryFailed, ex);
    }

    public static LogoutFailure HistoryQueryFailed(Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.QueryFailed,
            LogoutMessageKeys.HistoryQueryFailed, ex);
    }

    public static LogoutFailure MostRecentQueryFailed(Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.QueryFailed,
            LogoutMessageKeys.MostRecentQueryFailed, ex);
    }

    public static LogoutFailure DeviceQueryFailed(Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.QueryFailed,
            LogoutMessageKeys.DeviceQueryFailed, ex);
    }

    public static LogoutFailure NotFound(string? details = null)
    {
        return new LogoutFailure(LogoutFailureType.NotFound,
            details ?? LogoutMessageKeys.LogoutNotFound);
    }

    public static LogoutFailure HistoryNotFound()
    {
        return new LogoutFailure(LogoutFailureType.NotFound,
            LogoutMessageKeys.LogoutHistoryNotFound);
    }

    public static LogoutFailure ByDeviceNotFound()
    {
        return new LogoutFailure(LogoutFailureType.NotFound,
            LogoutMessageKeys.LogoutByDeviceNotFound);
    }

    public static LogoutFailure ValidationFailed(string? details = null)
    {
        return new LogoutFailure(LogoutFailureType.ValidationFailed,
            details ?? LogoutMessageKeys.Generic);
    }

    public static LogoutFailure MembershipIdInvalid()
    {
        return new LogoutFailure(LogoutFailureType.ValidationFailed,
            LogoutMessageKeys.MembershipIdInvalid);
    }

    public static LogoutFailure DeviceIdInvalid()
    {
        return new LogoutFailure(LogoutFailureType.ValidationFailed,
            LogoutMessageKeys.DeviceIdInvalid);
    }

    public static LogoutFailure ReasonInvalid()
    {
        return new LogoutFailure(LogoutFailureType.ValidationFailed,
            LogoutMessageKeys.ReasonInvalid);
    }

    public static LogoutFailure PersistorAccess(string? details = null, Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.PersistorAccess,
            details ?? LogoutMessageKeys.DataAccess, ex);
    }

    public static LogoutFailure DatabaseError(Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.PersistorAccess,
            LogoutMessageKeys.DatabaseError, ex);
    }

    public static LogoutFailure Timeout(Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.PersistorAccess,
            LogoutMessageKeys.Timeout, ex);
    }

    public static LogoutFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new LogoutFailure(LogoutFailureType.InternalError,
            details ?? LogoutMessageKeys.Generic, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            LogoutFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            LogoutFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            LogoutFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            LogoutFailureType.QueryFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            LogoutFailureType.RecordFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18NKey)
        };
    }

    private static string GetDefaultI18NKey(LogoutFailureType failureType) =>
        failureType switch
        {
            LogoutFailureType.NotFound => ErrorI18NKeys.NotFound,
            LogoutFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            LogoutFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
            LogoutFailureType.QueryFailed => ErrorI18NKeys.DatabaseUnavailable,
            LogoutFailureType.RecordFailed => ErrorI18NKeys.ServiceUnavailable,
            _ => ErrorI18NKeys.Internal
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
