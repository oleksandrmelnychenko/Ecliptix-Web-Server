namespace Ecliptix.Domain.Memberships.Failures;

public static class MobileNumberMessageKeys
{
    public const string MobileNumberInvalid = "mobile_invalid";
    public const string MobileNumberCannotBeEmpty = "mobile_cannot_be_empty";
    public const string MobileNumberEmpty = "mobile_number_empty";
    public const string MobileNumberTooShort = "mobile_parsing_too_short";
    public const string MobileNumberTooLong = "mobile_parsing_too_long";
    public const string InvalidCountryCode = "mobile_parsing_invalid_country_code";
    public const string InvalidNumber = "mobile_parsing_invalid_number";

    public const string ParsingGenericError = "mobile_parsing_generic_error";
    public const string ParsingPossibleButLocalOnly = "mobile_parsing_possible_but_local_only";
    public const string ParsingFailed = "mobile_parsing_failed";
    public const string InvalidDefaultRegion = "invalid_default_region";

    public const string MobileNumberNotFoundEntity = "mobile_number_not_found_entity";
    public const string MobileNotFound = "mobile_number_not_found";

    public const string EnsureMobileFailed = "ensure_mobile_failed";
    public const string GetMobileFailed = "get_mobile_failed";
    public const string CheckMobileAvailabilityFailed = "check_mobile_availability_failed";

    public const string DataAccess = "mobile_data_access_failed";
    public const string DatabaseError = "mobile_database_error";
    public const string Timeout = "mobile_operation_timeout";
    public const string ValidationUnexpectedError = "mobile_validation_unexpected_error";

    public const string Generic = "mobile_error_generic";
}
