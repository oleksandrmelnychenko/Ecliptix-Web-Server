namespace Ecliptix.Domain.Memberships.Failures;

public static class AccountMessageKeys
{
    public const string AccountNotFoundById = "account_not_found_by_id";
    public const string AccountNotFoundByMembership = "account_not_found_by_membership";

    public const string AccountAlreadyExists = "account_already_exists";

    public const string CreateAccountFailed = "create_account_failed";

    public const string CredentialUpdateFailed = "account_credential_update_failed";

    public const string ValidationFailed = "account_validation_failed";

    public const string DatabaseError = "account_database_error";
    public const string Timeout = "account_operation_timeout";
    public const string QueryFailed = "account_query_failed";

    public const string Generic = "account_error_generic";
}
