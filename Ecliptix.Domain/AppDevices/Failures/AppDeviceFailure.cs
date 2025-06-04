using Ecliptix.Domain.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.AppDevices.Failures;

public readonly struct AppDeviceFailure : IEquatable<AppDeviceFailure>
{
    public AppDeviceFailureType Type { get; }
    public string MessageKey { get; }
    public Option<Exception> Exception { get; }

    private AppDeviceFailure(AppDeviceFailureType type, string messageKey, Option<Exception> exception = default)
    {
        Type = type;
        MessageKey = messageKey;
        Exception = exception;
    }

    public static AppDeviceFailure PersistorAccess(string messageKey = AppDeviceMessageKeys.DataAccess,
        Exception? exception = null) =>
        new(AppDeviceFailureType.PersistorAccess, messageKey,
            exception != null ? Option<Exception>.Some(exception) : Option<Exception>.None);

    public static AppDeviceFailure Validation(string messageKey = AppDeviceMessageKeys.Validation,
        Exception? exception = null) =>
        new(AppDeviceFailureType.Validation, messageKey,
            exception != null ? Option<Exception>.Some(exception) : Option<Exception>.None);

    public static AppDeviceFailure Generic(string messageKey = AppDeviceMessageKeys.Generic,
        Exception? exception = null) =>
        new(AppDeviceFailureType.Generic, messageKey,
            exception != null ? Option<Exception>.Some(exception) : Option<Exception>.None);

    public bool IsRecoverable => Type switch
    {
        AppDeviceFailureType.PersistorAccess => true,
        AppDeviceFailureType.ConcurrencyConflict => true,
        AppDeviceFailureType.DeviceUpdateFailed => true,
        _ => false
    };

    public bool IsSecurityRelated => Type switch
    {
        AppDeviceFailureType.SecurityViolation => true,
        _ => false
    };

    public bool IsUserFacing => Type switch
    {
        AppDeviceFailureType.RegistrationFailed => true,
        AppDeviceFailureType.DeviceUpdateFailed => false,
        AppDeviceFailureType.PersistorAccess => false,
        AppDeviceFailureType.ConcurrencyConflict => false,
        AppDeviceFailureType.Validation => true,
        _ => false
    };

    public static Status ToGrpcStatus(AppDeviceFailure failure)
    {
        StatusCode code = failure.Type switch
        {
            AppDeviceFailureType.Validation => StatusCode.InvalidArgument,
            AppDeviceFailureType.PersistorAccess => StatusCode.Internal,
            AppDeviceFailureType.ConcurrencyConflict => StatusCode.Aborted,
            AppDeviceFailureType.DeviceUpdateFailed => StatusCode.FailedPrecondition,
            AppDeviceFailureType.RegistrationFailed => StatusCode.AlreadyExists,
            AppDeviceFailureType.SecurityViolation => StatusCode.PermissionDenied,
            AppDeviceFailureType.Generic => StatusCode.Internal,
            _ => StatusCode.Unknown
        };

        string message = code == StatusCode.Internal && failure.Type != AppDeviceFailureType.Generic
            ? "An internal error occurred."
            : failure.MessageKey;

        return new Status(code, message);
    }

    public bool Equals(AppDeviceFailure other) =>
        Type == other.Type && MessageKey == other.MessageKey;

    public override bool Equals(object? obj) =>
        obj is AppDeviceFailure other && Equals(other);

    public override int GetHashCode() =>
        HashCode.Combine(Type, MessageKey);

    public static bool operator ==(AppDeviceFailure left, AppDeviceFailure right) =>
        left.Equals(right);

    public static bool operator !=(AppDeviceFailure left, AppDeviceFailure right) =>
        !(left == right);

    public override string ToString() =>
        Exception.HasValue
            ? $"AppDeviceFailure({Type}, {MessageKey}, {Exception.Value.Message})"
            : $"AppDeviceFailure({Type}, {MessageKey})";

    public object ToStructuredLog() => new
    {
        Type = Type.ToString(),
        MessageKey,
        HasException = Exception.HasValue,
        ExceptionType = Exception.HasValue ? Exception.Value.GetType().Name : null,
        IsUserFacing,
        IsRecoverable,
        IsSecurityRelated
    };
}