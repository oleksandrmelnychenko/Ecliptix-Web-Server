namespace Ecliptix.Domain.Memberships.Failures;

/*
## **VF = Verification Flow**
## **Number Ranges = Error Categories**
- **(VF001-VF099)** = Session-related failures
    - VF001 = SessionNotFound
    - VF002 = SessionExpired
    - VF003 = SessionConflict
    - VF004-VF099 = Reserved for future session errors

    - **(VF101-VF199)** = OTP-related failures
    - VF101 = InvalidOtp
    - VF102 = OtpExpired
    - VF103 = OtpMaxAttemptsReached
    - VF104 = OtpGenerationFailed
    - VF105-VF199 = Reserved for future OTP errors

    - **(VF201-VF299)** = Communication failures
    - **(VF301-VF399)** = Data access failures
    - **(VF401-VF499)** = Security failures
    - **(VF501-VF599)** = Validation failures
    - **(VF999)** = Generic catch-all
    */

public static class VerificationFlowMessageKeys
{
    public const string SessionNotFound = "verification_flow.session.not_found";
    public const string SessionExpired = "verification_flow.session.expired";
    public const string SessionConflict = "verification_flow.session.conflict";

    // OTP-related failures (VF101-VF199)
    public const string InvalidOtp = "verification_flow.otp.invalid";
    public const string OtpExpired = "verification_flow.otp.expired";
    public const string OtpMaxAttemptsReached = "verification_flow.otp.max_attempts_reached";
    public const string OtpGenerationFailed = "verification_flow.otp.generation_failed";

    // Communication failures (VF201-VF299)
    public const string SmsSendFailed = "verification_flow.sms.send_failed";
    public const string PhoneNumberInvalid = "verification_flow.phone.invalid";

    // Data access failures (VF301-VF399)
    public const string DataAccess = "verification_flow.data.access_failed";
    public const string ConcurrencyConflict = "verification_flow.data.concurrency_conflict";

    // Security failures (VF401-VF499)
    public const string RateLimitExceeded = "verification_flow.security.rate_limit_exceeded";
    public const string SuspiciousActivity = "verification_flow.security.suspicious_activity";

    // Validation failures (VF501-VF599)
    public const string Validation = "verification_flow.validation.failed";
    
    // Password Manager specific validation failures (VF510-VF529)
    public const string PasswordManagerConfigIterations = "verification_flow.password.config.iterations_invalid";
    public const string PasswordManagerConfigSaltSize = "verification_flow.password.config.salt_size_invalid";
    public const string PasswordManagerConfigHashAlgorithm = "verification_flow.password.config.hash_algorithm_unsupported";
    public const string PasswordEmpty = "verification_flow.password.empty";
    public const string PasswordTooShort = "verification_flow.password.too_short";
    public const string PasswordMissingLowercase = "verification_flow.password.missing_lowercase";
    public const string PasswordMissingUppercase = "verification_flow.password.missing_uppercase";
    public const string PasswordMissingDigit = "verification_flow.password.missing_digit";
    public const string PasswordMissingSpecialChar = "verification_flow.password.missing_special_char";
    public const string PasswordInvalidChars = "verification_flow.password.invalid_chars";
    public const string PasswordHashInputEmpty = "verification_flow.password.hash_input_empty";
    public const string PasswordHashError = "verification_flow.password.hash_error";
    public const string PasswordVerifyInputEmpty = "verification_flow.password.verify_input_empty";
    public const string PasswordVerifyStoredHashEmpty = "verification_flow.password.verify_stored_hash_empty";
    public const string PasswordVerifyInvalidFormat = "verification_flow.password.verify_invalid_format";
    public const string PasswordVerifyBase64Error = "verification_flow.password.verify_base64_error";
    public const string PasswordVerifySaltSizeMismatch = "verification_flow.password.verify_salt_size_mismatch";
    public const string PasswordVerifyHashSizeMismatch = "verification_flow.password.verify_hash_size_mismatch";
    public const string PasswordVerifyMismatch = "verification_flow.password.verify_mismatch";
    public const string PasswordVerifyError = "verification_flow.password.verify_error";
    public const string PasswordComplexityRequirements = "verification_flow.password.complexity_requirements";

    // Generic (VF999)
    public const string Generic = "verification_flow.generic.error";
}