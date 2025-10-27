namespace Ecliptix.Domain.Memberships.Failures;

public static class PasswordRecoveryMessageKeys
{
    public const string TokenNotFound = "password_recovery_token_not_found";
    public const string TokenExpired = "password_recovery_token_expired";
    public const string TokenInvalid = "password_recovery_token_invalid";
    public const string TokenAlreadyUsed = "password_recovery_token_already_used";
    public const string TokenGenerationFailed = "password_recovery_token_generation_failed";

    public const string InitiationFailed = "password_recovery_initiation_failed";
    public const string SendEmailFailed = "password_recovery_send_email_failed";
    public const string SendSmsFailed = "password_recovery_send_sms_failed";
    public const string AccountNotEligible = "password_recovery_account_not_eligible";

    public const string ResetFailed = "password_recovery_reset_failed";
    public const string PasswordUpdateFailed = "password_recovery_password_update_failed";
    public const string VerificationFailed = "password_recovery_verification_failed";

    public const string ValidationFailed = "password_recovery_validation_failed";
    public const string InvalidPassword = "password_recovery_invalid_password";
    public const string PasswordTooWeak = "password_recovery_password_too_weak";

    public const string DataAccess = "password_recovery_data_access_failed";
    public const string DatabaseError = "password_recovery_database_error";
    public const string Timeout = "password_recovery_operation_timeout";

    public const string Generic = "password_recovery_error_generic";
}
