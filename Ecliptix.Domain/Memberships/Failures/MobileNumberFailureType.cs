namespace Ecliptix.Domain.Memberships.Failures;

public enum MobileNumberFailureType : short
{
    NotFound,
    Invalid,
    AlreadyExists,
    ParsingFailed,
    ValidationFailed,
    TooShort,
    TooLong,
    InvalidCountryCode,
    PersistorAccess,
    InternalError
}
