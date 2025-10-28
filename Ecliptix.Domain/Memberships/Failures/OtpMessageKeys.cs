namespace Ecliptix.Domain.Memberships.Failures;

public static class OtpMessageKeys
{
    public const string OtpInvalid = "otp_invalid";
    public const string OtpExpired = "otp_expired";
    public const string OtpMaxAttemptsReached = "max_otp_attempts_reached";
    public const string OtpAlreadyUsed = "otp_already_used";

    public const string OtpGenerationFailed = "otp_generation_failed";
    public const string OtpCreationFailed = "create_otp_failed";
    public const string OtpUpdateFailed = "update_otp_failed";
    public const string UpdateOtpStatusFailed = "update_otp_status_failed";

    public const string OtpNotFound = "otp_not_found";
    public const string OtpNotFoundForAttemptIncrement = "otp_not_found_for_attempt_increment";
    public const string OtpNotFoundForLogging = "otp_not_found_for_logging";
    public const string OtpNotFoundForAttemptCount = "otp_not_found_for_attempt_count";
    public const string OtpNotFoundForVerification = "otp_not_found_for_verification";

    public const string IncrementAttemptCountFailed = "increment_attempt_count_failed";
    public const string LogAttemptFailed = "log_attempt_failed";
    public const string GetAttemptCountFailed = "get_attempt_count_failed";

    public const string DataAccess = "otp_data_access_failed";
    public const string DatabaseError = "otp_database_error";
    public const string Timeout = "otp_operation_timeout";

    public const string Generic = "otp_error_generic";
}
