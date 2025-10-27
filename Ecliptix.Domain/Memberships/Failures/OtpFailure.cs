using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record OtpFailure(
    OtpFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        OtpFailureType.PersistorAccess => true,
        OtpFailureType.GenerationFailed => true,
        OtpFailureType.UpdateFailed => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        OtpFailureType.Invalid => true,
        OtpFailureType.Expired => true,
        OtpFailureType.MaxAttemptsReached => true,
        OtpFailureType.AlreadyUsed => true,
        OtpFailureType.NotFound => false,
        OtpFailureType.GenerationFailed => false,
        OtpFailureType.ValidationFailed => true,
        _ => false
    };

    public static OtpFailure Invalid(string? details = null)
    {
        return new OtpFailure(OtpFailureType.Invalid,
            details ?? OtpMessageKeys.OtpInvalid);
    }

    public static OtpFailure Expired(string? details = null)
    {
        return new OtpFailure(OtpFailureType.Expired,
            details ?? OtpMessageKeys.OtpExpired);
    }

    public static OtpFailure MaxAttemptsReached(string? details = null)
    {
        return new OtpFailure(OtpFailureType.MaxAttemptsReached,
            details ?? OtpMessageKeys.OtpMaxAttemptsReached);
    }

    public static OtpFailure AlreadyUsed(string? details = null)
    {
        return new OtpFailure(OtpFailureType.AlreadyUsed,
            details ?? OtpMessageKeys.OtpAlreadyUsed);
    }

    public static OtpFailure NotFound(string? details = null)
    {
        return new OtpFailure(OtpFailureType.NotFound,
            details ?? OtpMessageKeys.OtpNotFound);
    }

    public static OtpFailure NotFoundForAttemptIncrement()
    {
        return new OtpFailure(OtpFailureType.NotFound,
            OtpMessageKeys.OtpNotFoundForAttemptIncrement);
    }

    public static OtpFailure NotFoundForLogging()
    {
        return new OtpFailure(OtpFailureType.NotFound,
            OtpMessageKeys.OtpNotFoundForLogging);
    }

    public static OtpFailure NotFoundForAttemptCount()
    {
        return new OtpFailure(OtpFailureType.NotFound,
            OtpMessageKeys.OtpNotFoundForAttemptCount);
    }

    public static OtpFailure NotFoundForVerification()
    {
        return new OtpFailure(OtpFailureType.NotFound,
            OtpMessageKeys.OtpNotFoundForVerification);
    }

    public static OtpFailure GenerationFailed(string? details = null, Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.GenerationFailed,
            details ?? OtpMessageKeys.OtpGenerationFailed, ex);
    }

    public static OtpFailure CreationFailed(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            OtpMessageKeys.OtpCreationFailed, ex);
    }

    public static OtpFailure UpdateFailed(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.UpdateFailed,
            OtpMessageKeys.OtpUpdateFailed, ex);
    }

    public static OtpFailure UpdateStatusFailed(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.UpdateFailed,
            OtpMessageKeys.UpdateOtpStatusFailed, ex);
    }

    public static OtpFailure IncrementAttemptCountFailed(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            OtpMessageKeys.IncrementAttemptCountFailed, ex);
    }

    public static OtpFailure LogAttemptFailed(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            OtpMessageKeys.LogAttemptFailed, ex);
    }

    public static OtpFailure GetAttemptCountFailed(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            OtpMessageKeys.GetAttemptCountFailed, ex);
    }

    public static OtpFailure ValidationFailed(string? details = null)
    {
        return new OtpFailure(OtpFailureType.ValidationFailed,
            details ?? OtpMessageKeys.Generic);
    }

    public static OtpFailure PersistorAccess(string? details = null, Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            details ?? OtpMessageKeys.DataAccess, ex);
    }

    public static OtpFailure DatabaseError(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            OtpMessageKeys.DatabaseError, ex);
    }

    public static OtpFailure Timeout(Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.PersistorAccess,
            OtpMessageKeys.Timeout, ex);
    }

    public static OtpFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new OtpFailure(OtpFailureType.InternalError,
            details ?? OtpMessageKeys.Generic, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            OtpFailureType.Invalid => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            OtpFailureType.Expired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18NKey),
            OtpFailureType.MaxAttemptsReached => new GrpcErrorDescriptor(
                ErrorCode.MaxAttemptsReached,
                StatusCode.ResourceExhausted,
                i18NKey),
            OtpFailureType.AlreadyUsed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            OtpFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            OtpFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            OtpFailureType.GenerationFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            OtpFailureType.UpdateFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            OtpFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18NKey)
        };
    }

    private static string GetDefaultI18NKey(OtpFailureType failureType) =>
        failureType switch
        {
            OtpFailureType.Invalid => OtpMessageKeys.OtpInvalid,
            OtpFailureType.Expired => ErrorI18NKeys.OtpExpired,
            OtpFailureType.MaxAttemptsReached => ErrorI18NKeys.MaxAttempts,
            OtpFailureType.AlreadyUsed => OtpMessageKeys.OtpAlreadyUsed,
            OtpFailureType.NotFound => ErrorI18NKeys.NotFound,
            OtpFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            OtpFailureType.GenerationFailed => ErrorI18NKeys.ServiceUnavailable,
            OtpFailureType.UpdateFailed or OtpFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
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
            IsRecoverable,
            IsUserFacing
        };
    }
}
