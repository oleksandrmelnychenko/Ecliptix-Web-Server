namespace Ecliptix.Domain.Memberships;

internal static class LocalizationKeys
{
    public const string PhoneNotFound = "verification.error.phone_not_found";
    public const string SessionConflictUnresolved = "verification.error.session_conflict_unresolved";
    public const string SessionNotFoundOrInvalid = "verification.error.session_not_found_or_invalid";
    public const string MaxOtpAttemptsReached = "verification.error.max_otp_attempts_reached";
    public const string InvalidAppDeviceId = "verification.error.invalid_app_device_id";
    public const string CreatedButInvalidAppDeviceId = "verification.warning.created_but_invalid_app_device_id";
    public const string DatabaseTimeout = "verification.error.database_timeout";
    public const string UnexpectedOutcome = "verification.error.unexpected_outcome";
    public const string NoResultReturned = "verification.error.no_result_returned";
    
    public const string LoginNoResultsError = "Stored procedure login_membership returned no results.";
    public const string CreateNoResultsError = "Stored procedure create_membership returned no results.";
    public const string UpdateNoResultsError = "Stored procedure update_membership_secure_key returned no results.";
    public const string MissingRequiredData = "Missing required data in update response";
    public const string TooManyLoginAttempts = "membership.login.too_many_attempts";
    public const string TooManyMembershipAttempts = "membership.create.too_many_attempts";
    public const string InvalidActivityStatus = "membership.status.invalid";
    public const string NoActiveSessionOrOtp = "verification_flow.session.no_active_session_or_otp";
    public const string InvalidOtp = "verification_flow.otp.invalid";
    public const string VerificationSucceeded = "verification_flow.verification.succeeded";
}
