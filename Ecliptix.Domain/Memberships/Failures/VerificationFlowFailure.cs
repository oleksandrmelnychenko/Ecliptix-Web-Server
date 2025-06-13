namespace Ecliptix.Domain.Memberships.Failures;

public readonly struct VerificationFlowFailure : IEquatable<VerificationFlowFailure>
{
    public VerificationFlowFailureType FailureType { get; }
    public string Message { get; }
    public Exception? InnerException { get; }
    public string ErrorCode { get; }
    public DateTime Timestamp { get; }

    private VerificationFlowFailure(
        VerificationFlowFailureType failureType,
        string message,
        string errorCode,
        Exception? innerException = null)
    {
        FailureType = failureType;
        Message = message;
        ErrorCode = errorCode;
        InnerException = innerException;
        Timestamp = DateTime.UtcNow;
    }

    public static VerificationFlowFailure NotFound(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.NotFound,
            details ?? VerificationFlowMessageKeys.VerificationFlowNotFound,
            ErrorCodes.SessionNotFound);
    }

    public static VerificationFlowFailure Expired(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Expired,
            details ?? VerificationFlowMessageKeys.VerificationFlowExpired,
            ErrorCodes.SessionExpired);
    }

    public static VerificationFlowFailure Conflict(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Conflict,
            details ?? VerificationFlowMessageKeys.VerificationFlowConflict,
            ErrorCodes.SessionConflict);
    }

    public static VerificationFlowFailure InvalidOtp(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.InvalidOtp,
            details ?? VerificationFlowMessageKeys.InvalidOtp,
            ErrorCodes.InvalidOtp);
    }

    public static VerificationFlowFailure OtpExpired(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.OtpExpired,
            details ?? VerificationFlowMessageKeys.OtpExpired,
            ErrorCodes.OtpExpired);
    }

    public static VerificationFlowFailure OtpMaxAttemptsReached(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.OtpMaxAttemptsReached,
            details ?? VerificationFlowMessageKeys.OtpMaxAttemptsReached,
            ErrorCodes.OtpMaxAttemptsReached);
    }

    public static VerificationFlowFailure
        OtpGenerationFailed(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.OtpGenerationFailed,
            details ?? VerificationFlowMessageKeys.OtpGenerationFailed,
            ErrorCodes.OtpGenerationFailed,
            innerException);
    }

    public static VerificationFlowFailure SmsSendFailed(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.SmsSendFailed,
            details ?? VerificationFlowMessageKeys.SmsSendFailed,
            ErrorCodes.SmsSendFailed,
            innerException);
    }

    public static VerificationFlowFailure
        PhoneNumberInvalid(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PhoneNumberInvalid,
            details ?? VerificationFlowMessageKeys.PhoneNumberInvalid,
            ErrorCodes.PhoneNumberInvalid, innerException);
    }

    public static VerificationFlowFailure PersistorAccess(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            details ?? VerificationFlowMessageKeys.DataAccess,
            ErrorCodes.PersistorAccess,
            innerException);
    }

    public static VerificationFlowFailure PersistorAccess(Exception innerException)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.PersistorAccess,
            VerificationFlowMessageKeys.DataAccess,
            ErrorCodes.PersistorAccess,
            innerException);
    }

    public static VerificationFlowFailure ConcurrencyConflict(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.ConcurrencyConflict,
            details ?? VerificationFlowMessageKeys.ConcurrencyConflict,
            ErrorCodes.ConcurrencyConflict);
    }

    public static VerificationFlowFailure RateLimitExceeded(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.RateLimitExceeded,
            details ?? VerificationFlowMessageKeys.RateLimitExceeded,
            ErrorCodes.RateLimitExceeded);
    }

    public static VerificationFlowFailure Validation(string? details = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Validation,
            details ?? VerificationFlowMessageKeys.Validation,
            ErrorCodes.Validation);
    }

    public static VerificationFlowFailure Generic(string? details = null, Exception? innerException = null)
    {
        return new VerificationFlowFailure(VerificationFlowFailureType.Generic,
            details ?? VerificationFlowMessageKeys.Generic,
            ErrorCodes.Generic,
            innerException);
    }

    private static class ErrorCodes
    {
        public const string SessionNotFound = "VF001";
        public const string SessionExpired = "VF002";
        public const string SessionConflict = "VF003";
        public const string InvalidOtp = "VF101";
        public const string OtpExpired = "VF102";
        public const string OtpMaxAttemptsReached = "VF103";
        public const string OtpGenerationFailed = "VF104";
        public const string SmsSendFailed = "VF201";
        public const string PhoneNumberInvalid = "VF202";
        public const string PersistorAccess = "VF301";
        public const string ConcurrencyConflict = "VF302";
        public const string RateLimitExceeded = "VF401";
        public const string Validation = "VF501";
        public const string Generic = "VF999";
    }

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
        _ => false
    };

    /// <summary>
    ///     Determines if this failure should be shown to the user with a localized message.
    ///     Returns true for user-facing errors that can be safely displayed in the UI.
    /// </summary>
    public bool IsUserFacing => FailureType switch
    {
        // Session-related failures - user can understand and act on these
        VerificationFlowFailureType.NotFound => true,
        VerificationFlowFailureType.Expired => true,
        VerificationFlowFailureType.Conflict => false, // Internal conflict, not user actionable

        // OTP-related failures - most are user actionable
        VerificationFlowFailureType.InvalidOtp => true,
        VerificationFlowFailureType.OtpExpired => true,
        VerificationFlowFailureType.OtpMaxAttemptsReached => true,
        VerificationFlowFailureType.OtpGenerationFailed => false, // Technical issue

        // Communication failures - mixed
        VerificationFlowFailureType.SmsSendFailed => true, // User should know SMS failed
        VerificationFlowFailureType.PhoneNumberInvalid => true,

        // Data access failures - should not expose to user
        VerificationFlowFailureType.PersistorAccess => false, // Technical database issue
        VerificationFlowFailureType.ConcurrencyConflict => false, // Technical issue

        // Security failures - show rate limiting, hide suspicious activity details
        VerificationFlowFailureType.RateLimitExceeded => true,
        VerificationFlowFailureType.SuspiciousActivity => false, // Don't reveal security detection

        // Validation failures - usually user actionable
        VerificationFlowFailureType.Validation => true,

        // Generic - depends on context, default to not user-facing for safety
        VerificationFlowFailureType.Generic => false,

        _ => false
    };

    // Proper IEquatable<VerificationFlowFailure> implementation
    public bool Equals(VerificationFlowFailure other)
    {
        return FailureType == other.FailureType &&
               Message == other.Message &&
               ErrorCode == other.ErrorCode;
    }

    public override bool Equals(object? obj)
    {
        return obj is VerificationFlowFailure other && Equals(other);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(FailureType, Message, ErrorCode);
    }

    public static bool operator ==(VerificationFlowFailure left, VerificationFlowFailure right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(VerificationFlowFailure left, VerificationFlowFailure right)
    {
        return !left.Equals(right);
    }

    public override string ToString()
    {
        return $"[{ErrorCode}] {FailureType}: {Message}";
    }

    public object ToStructuredLog()
    {
        return new
        {
            ErrorCode,
            Type = FailureType.ToString(),
            Message,
            Timestamp,
            HasInnerException = InnerException != null,
            InnerExceptionType = InnerException?.GetType().Name,
            IsUserFacing,
            IsRecoverable,
            IsSecurityRelated
        };
    }
}