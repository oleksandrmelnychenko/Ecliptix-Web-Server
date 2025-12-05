namespace Ecliptix.Domain.Memberships.MobileNumberValidation;

public enum ValidationFailureReason
{
    InvalidNumber,
    InvalidCountryCode,
    TooShort,
    TooLong,
    PossibleButNotCertain
}
