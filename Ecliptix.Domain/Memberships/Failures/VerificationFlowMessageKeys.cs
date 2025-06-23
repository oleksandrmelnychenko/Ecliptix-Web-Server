namespace Ecliptix.Domain.Memberships.Failures;

public static class VerificationFlowMessageKeys
{
    public const string VerificationFlowExpired = "flow_expired";
    public const string VerificationFlowNotFound = "verification_flow_not_found";
    public const string CreateMembershipVerificationFlowNotFound = "verification_session_not_found";

    public const string InvalidOtp = "otp_invalid";
    public const string OtpGenerationFailed = "otp_generation_failed";
    public const string OtpMaxAttemptsReached = "max_otp_attempts_reached";
    public const string ResendAllowed = "resend_allowed";

    public const string ResendCooldown = "resend_cooldown_active";

    public const string AuthenticationCodeIs = "authentication_code_is";

    public const string PhoneNumberInvalid = "phone_invalid";
    
    public const string InvalidOpaque = "invalid_opaque";

    public const string ConcurrencyConflict = "data_concurrency_conflict";
    public const string DataAccess = "data_access_failed";

    public const string RateLimitExceeded = "security_rate_limit_exceeded";
    public const string TooManyMembershipAttempts = "membership_too_many_attempts";
    public const string TooManySigninAttempts = "signin_too_many_attempts";

    public const string ActivityStatusInvalid = "activity_status_invalid";
    public const string PhoneNumberCannotBeEmpty = "phone_cannot_be_empty";
    public const string PhoneNotFound = "phone_not_found";
    public const string Validation = "validation_failed";

    public const string InvalidCredentials = "invalid_credentials";
    public const string PasswordComplexityRequirements = "password_complexity_requirements";
    public const string PasswordEmpty = "password_empty";
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

    public const string Created = "created";
    public const string Generic = "generic_error";

    public const string PhoneNumberEmpty = "phone_number_empty";
    public const string InvalidDefaultRegion = "invalid_default_region";
    public const string PhoneParsingInvalidCountryCode = "phone_parsing_invalid_country_code";
    public const string PhoneParsingInvalidNumber = "phone_parsing_invalid_number";
    public const string PhoneParsingTooShort = "phone_parsing_too_short";
    public const string PhoneParsingTooLong = "phone_parsing_too_long";
    public const string PhoneParsingGenericError = "phone_parsing_generic_error";
    public const string PhoneParsingPossibleButLocalOnly = "phone_parsing_possible_but_local_only";
    public const string PhoneValidationUnexpectedError = "phone_validation_unexpected_error";
}