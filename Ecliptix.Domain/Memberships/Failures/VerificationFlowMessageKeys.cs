namespace Ecliptix.Domain.Memberships.Failures;

public static class VerificationFlowMessageKeys
{
    public const string VerificationFlowExpired = "flow_expired";
    public const string VerificationFlowNotFound = "verification_flow_not_exist";
    public const string FlowNotFound = "flow_not_found";
    public const string FlowNotFoundAfterCreation = "flow_not_found_after_creation";
    public const string FlowNotFoundOrInvalid = "flow_not_found_or_invalid";

    public const string InvalidOtp = "otp_invalid";
    public const string OtpNotFound = "otp_not_found";
    public const string OtpNotFoundForAttemptIncrement = "otp_not_found_for_attempt_increment";
    public const string OtpNotFoundForLogging = "otp_not_found_for_logging";
    public const string OtpNotFoundForAttemptCount = "otp_not_found_for_attempt_count";
    public const string OtpGenerationFailed = "otp_generation_failed";
    public const string OtpMaxAttemptsReached = "max_otp_attempts_reached";
    public const string ResendAllowed = "resend_allowed";

    public const string ResendCooldown = "resend_cooldown_active";

    public const string AuthenticationCodeIs = "authentication_code_is";

    public const string MobileNumberInvalid = "mobile_invalid";
    public const string MobileNumberNotFoundEntity = "mobile_number_not_found_entity";
    public const string SmsSendFailed = "sms_send_failed";

    public const string InvalidOpaque = "invalid_opaque";

    public const string ConcurrencyConflict = "data_concurrency_conflict";
    public const string DataAccess = "data_access_failed";

    public const string RateLimitExceeded = "security_rate_limit_exceeded";
    public const string MobileOtpLimitExhausted = "mobile_otp_limit_exhausted";

    public const string MobileNumberCannotBeEmpty = "mobile_cannot_be_empty";
    public const string MobileNotFound = "mobile_number_not_found";
    public const string Validation = "validation_failed";

    public const string InvalidCredentials = "invalid_credentials";
    public const string PasswordRecoveryOtpRequired = "password_recovery_otp_required";

    public const string MembershipNotFound = "membership_not_found";
    public const string AccountNotFound = "account_not_found";
    public const string DefaultAccountNotFound = "default_account_not_found";
    public const string CredentialsNotFound = "credentials_not_found";
    public const string DeviceNotFound = "device_not_found";

    public const string UpdateMembershipFailed = "update_membership_failed";
    public const string CreateMembershipFailed = "create_membership_failed";
    public const string InitiateFlowFailed = "initiate_flow_failed";
    public const string RequestResendFailed = "request_resend_failed";
    public const string UpdateOtpStatusFailed = "update_otp_status_failed";
    public const string GetMobileFailed = "get_mobile_failed";
    public const string UpdateFlowStatusFailed = "update_flow_status_failed";
    public const string CheckExistingMembershipFailed = "check_existing_membership_failed";
    public const string CheckMobileAvailabilityFailed = "check_mobile_availability_failed";
    public const string CreateOtpFailed = "create_otp_failed";
    public const string EnsureMobileFailed = "ensure_mobile_failed";
    public const string IncrementAttemptCountFailed = "increment_attempt_count_failed";
    public const string LogAttemptFailed = "log_attempt_failed";

    public const string DeviceRateLimitExceeded = "device_rate_limit_exceeded";

    public const string Generic = "generic_error";

    public const string MobileNumberEmpty = "mobile_number_empty";
    public const string InvalidDefaultRegion = "invalid_default_region";
    public const string MobileParsingInvalidCountryCode = "mobile_parsing_invalid_country_code";
    public const string MobileParsingInvalidNumber = "mobile_parsing_invalid_number";
    public const string MobileParsingTooShort = "mobile_parsing_too_short";
    public const string MobileParsingTooLong = "mobile_parsing_too_long";
    public const string MobileParsingGenericError = "mobile_parsing_generic_error";
    public const string MobileParsingPossibleButLocalOnly = "mobile_parsing_possible_but_local_only";
    public const string MobileValidationUnexpectedError = "mobile_validation_unexpected_error";

    public const string MobileAvailableForRegistration = "mobile_available_for_registration";
    public const string MobileIncompleteRegistration = "mobile_incomplete_registration_continue";
    public const string MobileTakenActiveAccount = "mobile_taken_active_account";
    public const string MobileTakenInactiveAccount = "mobile_taken_inactive_account";
    public const string MobileDataCorruption = "mobile_data_corruption_contact_support";
    public const string MobileAvailableOnThisDevice = "mobile_available_on_this_device";
    public const string MobileRegistrationExpired = "mobile_registration_window_expired";
}
