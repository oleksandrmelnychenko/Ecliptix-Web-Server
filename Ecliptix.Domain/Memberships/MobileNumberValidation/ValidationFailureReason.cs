namespace Ecliptix.Domain.Memberships.MobileNumberValidation;

public enum ValidationFailureReason
{
    ParsingFailed,
    InvalidNumber,
    InvalidCountryCode,
    TooShort,
    TooLong,
    InvalidForRegion,
    PossibleButNotCertain,
    InternalError
}
