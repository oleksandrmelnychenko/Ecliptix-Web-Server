namespace Ecliptix.Domain.Memberships.Failures;

public static class AccountProfileMessageKeys
{
    public const string ProfileNotFound = "profile_not_found";
    public const string AccountNotFound = "account_not_found";

    public const string ProfileNameTaken = "profile_name_taken";
    public const string ProfileAlreadyExists = "profile_already_exists";

    public const string ValidationFailed = "profile_validation_failed";
    public const string InvalidProfileName = "invalid_profile_name";
    public const string InvalidDisplayName = "invalid_display_name";
    public const string ProfileNameTooShort = "profile_name_too_short";
    public const string ProfileNameTooLong = "profile_name_too_long";
    public const string InvalidCharacters = "profile_name_invalid_characters";

    public const string DataAccess = "profile_data_access_failed";
    public const string QueryFailed = "profile_query_failed";
    public const string UpdateFailed = "profile_update_failed";
    public const string CheckAvailabilityFailed = "check_availability_failed";
    public const string ConcurrencyConflict = "profile_concurrency_conflict";
    public const string Timeout = "profile_operation_timeout";

    public const string Generic = "profile_generic_error";
    public const string UnexpectedError = "profile_unexpected_error";
    public const string DatabaseError = "profile_database_error";
}
