namespace Ecliptix.Domain.Memberships.PhoneNumberValidation;

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