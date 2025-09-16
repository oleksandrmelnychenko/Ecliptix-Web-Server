namespace Ecliptix.Domain.Memberships.Failures;

public static class VerificationFlowMessageKeys
{
    public const string VerificationFlowExpired = "flow_expired";
    public const string VerificationFlowNotFound = "verification_flow_not_found";
    public const string CreateMembershipVerificationFlowNotFound = "verification_session_not_found";

    public const string InvalidOtp = "otp_invalid";
    public const string GlobalRateLimitExceeded = "global_rate_limit_exceeded";
    public const string OtpGenerationFailed = "otp_generation_failed";
    public const string OtpMaxAttemptsReached = "max_otp_attempts_reached";
    public const string ResendAllowed = "resend_allowed";

    public const string ResendCooldown = "resend_cooldown_active";

    public const string AuthenticationCodeIs = "authentication_code_is";

    public const string PhoneNumberInvalid = "phone_invalid";
    public const string SmsSendFailed = "sms_send_failed";

    public const string InvalidOpaque = "invalid_opaque";

    public const string ConcurrencyConflict = "data_concurrency_conflict";
    public const string DataAccess = "data_access_failed";

    public const string RateLimitExceeded = "security_rate_limit_exceeded";
    public const string TooManyMembershipAttempts = "membership_too_many_attempts";
    public const string TooManySigninAttempts = "signin_too_many_attempts";

    public const string ActivityStatusInvalid = "activity_status_invalid";
    public const string PhoneNumberCannotBeEmpty = "phone_cannot_be_empty";
    public const string PhoneNotFound = "phone_number_not_found";
    public const string Validation = "validation_failed";

    public const string InvalidCredentials = "invalid_credentials";
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