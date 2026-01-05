namespace Ecliptix.IdentityAccess.Domain.Memberships.MobileNumberValidation;

public enum ValidationFailureReason
{
    InvalidNumber,
    InvalidCountryCode,
    TooShort,
    TooLong,
    PossibleButNotCertain
}
