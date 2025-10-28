using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record VerificationFlowFailure(
    VerificationFlowFailureType FailureType,
    string Message,
    FailureBase? SourceFailure = null,
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
        _ => false
    };

    public static VerificationFlowFailure NotFound(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.NotFound,
            details ?? VerificationFlowMessageKeys.VerificationFlowNotFound);
    }

    public static VerificationFlowFailure FlowNotFound()
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.NotFound,
            VerificationFlowMessageKeys.FlowNotFound);
    }

    public static VerificationFlowFailure FlowNotFoundAfterCreation()
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.NotFound,
            VerificationFlowMessageKeys.FlowNotFoundAfterCreation);
    }

    public static VerificationFlowFailure FlowNotFoundOrInvalid()
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.NotFound,
            VerificationFlowMessageKeys.FlowNotFoundOrInvalid);
    }


    public static VerificationFlowFailure
        OtpGenerationFailed(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.OtpGenerationFailed,
            details ?? VerificationFlowMessageKeys.OtpGenerationFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure
        MobileNumberInvalid(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.MobileNumberInvalid,
            details ?? VerificationFlowMessageKeys.MobileNumberInvalid, InnerException: innerException);
    }

    public static VerificationFlowFailure
        SmsSendFailed(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.SmsSendFailed,
            details ?? VerificationFlowMessageKeys.SmsSendFailed, InnerException: innerException);
    }

    public static VerificationFlowFailure PersistorAccess(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            details ?? VerificationFlowMessageKeys.DataAccess,
            InnerException: innerException);
    }


    public static VerificationFlowFailure InitiateFlowFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.InitiateFlowFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure RequestResendFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.RequestResendFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure UpdateFlowStatusFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.UpdateFlowStatusFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure CheckMobileAvailabilityFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.CheckMobileAvailabilityFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure CreateOtpFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.CreateOtpFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure IncrementAttemptCountFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.IncrementAttemptCountFailed,
            InnerException: innerException);
    }

    public static VerificationFlowFailure LogAttemptFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.LogAttemptFailed,
            InnerException: innerException);
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

    public static VerificationFlowFailure DeviceRateLimitExceeded()
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.RateLimitExceeded,
            VerificationFlowMessageKeys.DeviceRateLimitExceeded);
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
            null,
            innerException);
    }

    public static VerificationFlowFailure UpdateOtpStatusFailed(Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            "OTP status update failed",
            InnerException: innerException);
    }

    public static VerificationFlowFailure FromOtp(OtpFailure otpFailure)
    {
        return otpFailure.FailureType switch
        {
            OtpFailureType.Invalid => new VerificationFlowFailure(
                VerificationFlowFailureType.InvalidOtp,
                otpFailure.Message,
                SourceFailure: otpFailure,
                otpFailure.InnerException),

            OtpFailureType.NotFound => new VerificationFlowFailure(
                VerificationFlowFailureType.NotFound,
                otpFailure.Message,
                SourceFailure: otpFailure,
                otpFailure.InnerException),

            OtpFailureType.MaxAttemptsReached => new VerificationFlowFailure(
                VerificationFlowFailureType.OtpMaxAttemptsReached,
                otpFailure.Message,
                SourceFailure: otpFailure,
                otpFailure.InnerException),

            OtpFailureType.GenerationFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.OtpGenerationFailed,
                otpFailure.Message,
                SourceFailure: otpFailure,
                otpFailure.InnerException),

            OtpFailureType.UpdateFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                otpFailure.Message,
                SourceFailure: otpFailure,
                otpFailure.InnerException),

            _ => new VerificationFlowFailure(
                VerificationFlowFailureType.Generic,
                otpFailure.Message,
                SourceFailure: otpFailure,
                otpFailure.InnerException)
        };
    }

    public static VerificationFlowFailure FromMobileNumber(MobileNumberFailure mobileFailure)
    {
        return mobileFailure.FailureType switch
        {
            MobileNumberFailureType.ValidationFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.MobileNumberInvalid,
                mobileFailure.Message,
                SourceFailure: mobileFailure,
                mobileFailure.InnerException),

            MobileNumberFailureType.NotFound => new VerificationFlowFailure(
                VerificationFlowFailureType.NotFound,
                mobileFailure.Message,
                SourceFailure: mobileFailure,
                mobileFailure.InnerException),

            MobileNumberFailureType.PersistorAccess => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                mobileFailure.Message,
                SourceFailure: mobileFailure,
                mobileFailure.InnerException),

            _ => new VerificationFlowFailure(
                VerificationFlowFailureType.Generic,
                mobileFailure.Message,
                SourceFailure: mobileFailure,
                mobileFailure.InnerException)
        };
    }

    public static VerificationFlowFailure FromMembership(MembershipFailure membershipFailure)
    {
        return membershipFailure.FailureType switch
        {
            MembershipFailureType.NotFound => new VerificationFlowFailure(
                VerificationFlowFailureType.NotFound,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.AlreadyExists => new VerificationFlowFailure(
                VerificationFlowFailureType.Conflict,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.ValidationFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.Validation,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.InvalidStatus => new VerificationFlowFailure(
                VerificationFlowFailureType.Validation,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.CreationFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.UpdateFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.StatusUpdateFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            MembershipFailureType.PersistorAccess => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException),

            _ => new VerificationFlowFailure(
                VerificationFlowFailureType.Generic,
                membershipFailure.Message,
                SourceFailure: membershipFailure,
                membershipFailure.InnerException)
        };
    }

    public static VerificationFlowFailure FromPasswordRecovery(PasswordRecoveryFailure passwordRecoveryFailure)
    {
        return passwordRecoveryFailure.FailureType switch
        {
            PasswordRecoveryFailureType.TokenNotFound => new VerificationFlowFailure(
                VerificationFlowFailureType.NotFound,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.TokenExpired => new VerificationFlowFailure(
                VerificationFlowFailureType.Expired,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.TokenInvalid => new VerificationFlowFailure(
                VerificationFlowFailureType.Unauthorized,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.TokenAlreadyUsed => new VerificationFlowFailure(
                VerificationFlowFailureType.Validation,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.InitiationFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.SmsSendFailed,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.ResetFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.ValidationFailed => new VerificationFlowFailure(
                VerificationFlowFailureType.Validation,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            PasswordRecoveryFailureType.PersistorAccess => new VerificationFlowFailure(
                VerificationFlowFailureType.PersistorAccess,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException),

            _ => new VerificationFlowFailure(
                VerificationFlowFailureType.Generic,
                passwordRecoveryFailure.Message,
                SourceFailure: passwordRecoveryFailure,
                passwordRecoveryFailure.InnerException)
        };
    }

    public T? GetSourceFailure<T>() where T : FailureBase => SourceFailure as T;

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            VerificationFlowFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            VerificationFlowFailureType.Expired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18NKey),
            VerificationFlowFailureType.InvalidOtp => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            VerificationFlowFailureType.OtpExpired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18NKey),
            VerificationFlowFailureType.MobileNumberInvalid => new GrpcErrorDescriptor(
                ErrorCode.InvalidMobileNumber,
                StatusCode.InvalidArgument,
                i18NKey),
            VerificationFlowFailureType.Validation => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            VerificationFlowFailureType.OtpMaxAttemptsReached => new GrpcErrorDescriptor(
                ErrorCode.MaxAttemptsReached,
                StatusCode.ResourceExhausted,
                i18NKey),
            VerificationFlowFailureType.RateLimitExceeded => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                i18NKey),
            VerificationFlowFailureType.SuspiciousActivity => new GrpcErrorDescriptor(
                ErrorCode.PermissionDenied,
                StatusCode.PermissionDenied,
                i18NKey),
            VerificationFlowFailureType.Unauthorized => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            VerificationFlowFailureType.ConcurrencyConflict => new GrpcErrorDescriptor(
                ErrorCode.Conflict,
                StatusCode.Aborted,
                i18NKey),
            VerificationFlowFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            VerificationFlowFailureType.SmsSendFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            VerificationFlowFailureType.OtpGenerationFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            VerificationFlowFailureType.InvalidOpaque => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18NKey)
        };
    }

    private static string GetDefaultI18NKey(VerificationFlowFailureType failureType) =>
        failureType switch
        {
            VerificationFlowFailureType.NotFound => ErrorI18NKeys.NotFound,
            VerificationFlowFailureType.Expired => ErrorI18NKeys.OtpExpired,
            VerificationFlowFailureType.Conflict => ErrorI18NKeys.Conflict,
            VerificationFlowFailureType.InvalidOtp => VerificationFlowMessageKeys.InvalidOtp,
            VerificationFlowFailureType.OtpExpired => ErrorI18NKeys.OtpExpired,
            VerificationFlowFailureType.OtpMaxAttemptsReached => ErrorI18NKeys.MaxAttempts,
            VerificationFlowFailureType.OtpGenerationFailed => VerificationFlowMessageKeys.OtpGenerationFailed,
            VerificationFlowFailureType.SmsSendFailed => VerificationFlowMessageKeys.SmsSendFailed,
            VerificationFlowFailureType.MobileNumberInvalid => ErrorI18NKeys.InvalidMobile,
            VerificationFlowFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
            VerificationFlowFailureType.ConcurrencyConflict => ErrorI18NKeys.Conflict,
            VerificationFlowFailureType.RateLimitExceeded => ErrorI18NKeys.ResourceExhausted,
            VerificationFlowFailureType.SuspiciousActivity => ErrorI18NKeys.PermissionDenied,
            VerificationFlowFailureType.Validation => ErrorI18NKeys.Validation,
            VerificationFlowFailureType.InvalidOpaque => VerificationFlowMessageKeys.InvalidOpaque,
            VerificationFlowFailureType.Unauthorized => ErrorI18NKeys.Unauthenticated,
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
            IsUserFacing,
            IsRecoverable,
            IsSecurityRelated
        };
    }
}
