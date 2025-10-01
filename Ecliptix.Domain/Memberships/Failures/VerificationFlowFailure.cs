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

    public static VerificationFlowFailure Generic(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Generic,
            details ?? VerificationFlowMessageKeys.Generic,
            innerException);
    }

    public override Status ToGrpcStatus()
    {
        StatusCode code = FailureType switch
        {
            VerificationFlowFailureType.NotFound => StatusCode.NotFound,
            VerificationFlowFailureType.Expired => StatusCode.Unauthenticated,
            VerificationFlowFailureType.InvalidOtp => StatusCode.Unauthenticated,
            VerificationFlowFailureType.OtpExpired => StatusCode.Unauthenticated,
            VerificationFlowFailureType.MobileNumberInvalid => StatusCode.InvalidArgument,
            VerificationFlowFailureType.Validation => StatusCode.InvalidArgument,

            VerificationFlowFailureType.OtpMaxAttemptsReached => StatusCode.ResourceExhausted,
            VerificationFlowFailureType.RateLimitExceeded => StatusCode.ResourceExhausted,
            VerificationFlowFailureType.SuspiciousActivity => StatusCode.PermissionDenied,

            VerificationFlowFailureType.ConcurrencyConflict => StatusCode.Aborted,
            VerificationFlowFailureType.PersistorAccess => StatusCode.Unavailable,
            VerificationFlowFailureType.SmsSendFailed => StatusCode.Unavailable,
            VerificationFlowFailureType.OtpGenerationFailed => StatusCode.Internal,
            VerificationFlowFailureType.Generic => StatusCode.Internal,

            _ => StatusCode.Unknown
        };

        return new Status(code, Message);
    }

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