namespace Ecliptix.Domain.Memberships.Failures;

public static class VerificationFlowMessageKeys
{
    public const string ConflictResolvedToExisting = "verification_flow_conflict_resolved_to_existing";
    public const string ConflictUnresolved = "verification_flow_conflict_unresolved";
    public const string ExistingSessionReusedAndUpdated = "verification_flow_reused_and_updated";
    public const string VerificationFlowConflict = "verification_flow_conflict";
    public const string VerificationFlowExpiredExpired = "verification_flow_expired";
    public const string VerificationFlowNotFound = "verification_flow_not_found"; 
    public const string VerificationFlowNotVerified = "verification_flow_not_verified";
    public const string CreateMembershipVerificationFlowNotFound = "verification_session_not_found";
    
    public const string InvalidOtp = "otp_invalid";
    public const string OtpExpired = "otp_expired";
    public const string OtpGenerationFailed = "otp_generation_failed";
    public const string OtpMaxAttemptsReached = "otp_max_attempts_reached";
    public const string OtpNotVerified = "otp_not_verified";

    public const string PhoneNumberInvalid = "phone_invalid";
    public const string SmsSendFailed = "sms_send_failed";

    public const string ConcurrencyConflict = "data_concurrency_conflict";
    public const string DataAccess = "data_access_failed";

    public const string RateLimitExceeded = "security_rate_limit_exceeded";
    public const string SuspiciousActivity = "security_suspicious_activity";
    public const string TooManyMembershipAttempts = "membership_too_many_attempts";
    public const string TooManySigninAttempts = "signin_too_many_attempts";

    public const string ActivityStatusInvalid = "activity_status_invalid";
    public const string AppDeviceCreatedButInvalidId = "app_device_created_but_invalid_id";
    public const string AppDeviceInvalidId = "app_device_invalid_id";
    public const string PhoneNumberAssociated = "associated";
    public const string PhoneNumberCannotBeEmpty = "phone_cannot_be_empty";
    public const string PhoneNumberCreatedAndAssociated = "created_and_associated";
    public const string PhoneNumberExists = "exists"; 
    public const string PhoneNumberLoginNotFound = "phone_number_not_found";
    public const string PhoneNotFound = "phone_not_found"; 
    public const string Validation = "validation_failed";

    public const string InvalidCredentials = "invalid_credentials";
    public const string PasswordComplexityRequirements = "password_complexity_requirements";
    public const string PasswordEmpty = "password_empty";
    public const string PasswordHashError = "password_hash_error";
    public const string PasswordHashInputEmpty = "password_hash_input_empty";
    public const string PasswordInvalidChars = "password_invalid_chars";
    public const string PasswordManagerConfigHashAlgorithm = "password_config_hash_algorithm_unsupported";
    public const string PasswordManagerConfigIterations = "password_config_iterations_invalid";
    public const string PasswordManagerConfigSaltSize = "password_config_salt_size_invalid";
    public const string PasswordMissingDigit = "password_missing_digit";
    public const string PasswordMissingLowercase = "password_missing_lowercase";
    public const string PasswordMissingSpecialChar = "password_missing_special_char";
    public const string PasswordMissingUppercase = "password_missing_uppercase";
    public const string PasswordTooShort = "password_too_short";
    public const string PasswordVerifyBase64Error = "password_verify_base64_error";
    public const string PasswordVerifyError = "password_verify_error";
    public const string PasswordVerifyHashSizeMismatch = "password_verify_hash_size_mismatch";
    public const string PasswordVerifyInputEmpty = "password_verify_input_empty";
    public const string PasswordVerifyInvalidFormat = "password_verify_invalid_format";
    public const string PasswordVerifyMismatch = "password_verify_mismatch";
    public const string PasswordVerifySaltSizeMismatch = "password_verify_salt_size_mismatch";
    public const string PasswordVerifyStoredHashEmpty = "password_verify_stored_hash_empty";

    public const string InactiveMembership = "inactive_membership";
    public const string InvalidSecureKey = "invalid_secure_key";
    public const string MembershipAlreadyExists = "membership_already_exists";
    public const string MembershipNotFound = "membership_not_found";
    public const string SecureKeyCannotBeEmpty = "secure_key_cannot_be_empty";
    public const string SecureKeyNotSet = "secure_key_not_set"; 
    public const string SecureKeyTooLong = "secure_key_too_long";
    public const string SecureKeyUpdated = "secure_key_updated"; 

    public const string Created = "created";
    public const string Generic = "generic_error";
    public const string NoResultReturned = "generic_no_result_returned";
    public const string Success = "generic_success"; 
    public const string UnexpectedOutcome = "generic_unexpected_outcome";
    
    public const string PhoneParsingInvalidCountryCode = "phone_parsing_invalid_country_code";
    public const string PhoneParsingTooShort = "phone_parsing_too_short";
    public const string PhoneParsingTooLong = "phone_parsing_too_long";
    public const string PhoneParsingInvalidNumber = "phone_parsing_invalid_number"; 
    public const string PhoneParsingPossibleButLocalOnly = "phone_parsing_possible_but_local_only";
    public const string PhoneParsingGenericError = "phone_parsing_generic_error"; 
    public const string PhoneValidationUnexpectedError = "phone_validation_unexpected_error"; 
}