using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record VerificationFlowFailure(
    VerificationFlowFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        VerificationFlowFailureType.RateLimitExceeded => true,
        VerificationFlowFailureType.SmsSendFailed => true,
        VerificationFlowFailureType.PersistorAccess => true,
        VerificationFlowFailureType.ConcurrencyConflict => true,
        _ => false
    };

    public bool IsSecurityRelated => FailureType switch
    {
        VerificationFlowFailureType.SuspiciousActivity => true,
        VerificationFlowFailureType.RateLimitExceeded => true,
        VerificationFlowFailureType.OtpMaxAttemptsReached => true,
        VerificationFlowFailureType.InvalidOpaque => true,
        VerificationFlowFailureType.Unauthorized => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        VerificationFlowFailureType.NotFound => true,
        VerificationFlowFailureType.Expired => true,
        VerificationFlowFailureType.Conflict => false,

        VerificationFlowFailureType.InvalidOtp => true,
        VerificationFlowFailureType.OtpExpired => true,
        VerificationFlowFailureType.OtpMaxAttemptsReached => true,
        VerificationFlowFailureType.OtpGenerationFailed => false,

        VerificationFlowFailureType.SmsSendFailed => true,
        VerificationFlowFailureType.MobileNumberInvalid => true,

        VerificationFlowFailureType.PersistorAccess => false,
        VerificationFlowFailureType.ConcurrencyConflict => false,

        VerificationFlowFailureType.RateLimitExceeded => true,
        VerificationFlowFailureType.SuspiciousActivity => false,

        VerificationFlowFailureType.Validation => true,
        VerificationFlowFailureType.InvalidOpaque => false,
        _ => false
    };

    public static VerificationFlowFailure InvalidOpaque(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.InvalidOpaque,
            details ?? VerificationFlowMessageKeys.InvalidOpaque);
    }

    public static VerificationFlowFailure NotFound(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.NotFound,
            details ?? VerificationFlowMessageKeys.VerificationFlowNotFound);
    }

    public static VerificationFlowFailure InvalidOtp(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.InvalidOtp,
            details ?? VerificationFlowMessageKeys.InvalidOtp);
    }

    public static VerificationFlowFailure OtpMaxAttemptsReached(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.OtpMaxAttemptsReached,
            details ?? VerificationFlowMessageKeys.OtpMaxAttemptsReached);
    }

    public static VerificationFlowFailure
        OtpGenerationFailed(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.OtpGenerationFailed,
            details ?? VerificationFlowMessageKeys.OtpGenerationFailed,
            innerException);
    }

    public static VerificationFlowFailure
        MobileNumberInvalid(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.MobileNumberInvalid,
            details ?? VerificationFlowMessageKeys.MobileNumberInvalid, innerException);
    }

    public static VerificationFlowFailure
        SmsSendFailed(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.SmsSendFailed,
            details ?? VerificationFlowMessageKeys.SmsSendFailed, innerException);
    }

    public static VerificationFlowFailure PersistorAccess(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            details ?? VerificationFlowMessageKeys.DataAccess,
            innerException);
    }

    public static VerificationFlowFailure PersistorAccess(Exception innerException)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.DataAccess,
            innerException);
    }

    public static VerificationFlowFailure ConcurrencyConflict(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.ConcurrencyConflict,
            details ?? VerificationFlowMessageKeys.ConcurrencyConflict);
    }

    public static VerificationFlowFailure RateLimitExceeded(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.RateLimitExceeded,
            details ?? VerificationFlowMessageKeys.RateLimitExceeded);
    }

    public static VerificationFlowFailure Validation(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Validation,
            details ?? VerificationFlowMessageKeys.Validation);
    }

    public static VerificationFlowFailure Unauthorized(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Unauthorized,
            details ?? "Unauthorized");
    }

    public static VerificationFlowFailure Generic(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Generic,
            details ?? VerificationFlowMessageKeys.Generic,
            innerException);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18nKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18nKey(FailureType) : Message;

        return FailureType switch
        {
            VerificationFlowFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18nKey),
            VerificationFlowFailureType.Expired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18nKey),
            VerificationFlowFailureType.InvalidOtp => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18nKey),
            VerificationFlowFailureType.OtpExpired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18nKey),
            VerificationFlowFailureType.MobileNumberInvalid => new GrpcErrorDescriptor(
                ErrorCode.InvalidMobileNumber,
                StatusCode.InvalidArgument,
                i18nKey),
            VerificationFlowFailureType.Validation => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18nKey),
            VerificationFlowFailureType.OtpMaxAttemptsReached => new GrpcErrorDescriptor(
                ErrorCode.MaxAttemptsReached,
                StatusCode.ResourceExhausted,
                i18nKey),
            VerificationFlowFailureType.RateLimitExceeded => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                i18nKey),
            VerificationFlowFailureType.SuspiciousActivity => new GrpcErrorDescriptor(
                ErrorCode.PermissionDenied,
                StatusCode.PermissionDenied,
                i18nKey),
            VerificationFlowFailureType.Unauthorized => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18nKey),
            VerificationFlowFailureType.ConcurrencyConflict => new GrpcErrorDescriptor(
                ErrorCode.Conflict,
                StatusCode.Aborted,
                i18nKey),
            VerificationFlowFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            VerificationFlowFailureType.SmsSendFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            VerificationFlowFailureType.OtpGenerationFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            VerificationFlowFailureType.InvalidOpaque => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18nKey),
            VerificationFlowFailureType.Generic => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18nKey),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18nKey)
        };
    }

    private static string GetDefaultI18nKey(VerificationFlowFailureType failureType) =>
        failureType switch
        {
            VerificationFlowFailureType.NotFound => ErrorI18nKeys.NotFound,
            VerificationFlowFailureType.Expired => ErrorI18nKeys.OtpExpired,
            VerificationFlowFailureType.Conflict => ErrorI18nKeys.Conflict,
            VerificationFlowFailureType.InvalidOtp => VerificationFlowMessageKeys.InvalidOtp,
            VerificationFlowFailureType.OtpExpired => ErrorI18nKeys.OtpExpired,
            VerificationFlowFailureType.OtpMaxAttemptsReached => ErrorI18nKeys.MaxAttempts,
            VerificationFlowFailureType.OtpGenerationFailed => VerificationFlowMessageKeys.OtpGenerationFailed,
            VerificationFlowFailureType.SmsSendFailed => VerificationFlowMessageKeys.SmsSendFailed,
            VerificationFlowFailureType.MobileNumberInvalid => ErrorI18nKeys.InvalidMobile,
            VerificationFlowFailureType.PersistorAccess => ErrorI18nKeys.DatabaseUnavailable,
            VerificationFlowFailureType.ConcurrencyConflict => ErrorI18nKeys.Conflict,
            VerificationFlowFailureType.RateLimitExceeded => ErrorI18nKeys.ResourceExhausted,
            VerificationFlowFailureType.SuspiciousActivity => ErrorI18nKeys.PermissionDenied,
            VerificationFlowFailureType.Validation => ErrorI18nKeys.Validation,
            VerificationFlowFailureType.InvalidOpaque => VerificationFlowMessageKeys.InvalidOpaque,
            VerificationFlowFailureType.Unauthorized => ErrorI18nKeys.Unauthenticated,
            VerificationFlowFailureType.Generic => ErrorI18nKeys.Internal,
            _ => ErrorI18nKeys.Internal
        };

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsUserFacing,
            IsRecoverable,
            IsSecurityRelated
        };
    }
}
