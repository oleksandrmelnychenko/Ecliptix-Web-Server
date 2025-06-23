namespace Ecliptix.Domain.Memberships.Failures;

public enum VerificationFlowFailureType : short
{
    NotFound,
    Expired,
    Conflict,

    InvalidOtp,
    OtpExpired,
    OtpMaxAttemptsReached,
    OtpGenerationFailed,

    SmsSendFailed,
    PhoneNumberInvalid,

    PersistorAccess,
    ConcurrencyConflict,

    RateLimitExceeded,
    SuspiciousActivity,

    Validation,
    
    InvalidOpaque,

    Generic
}