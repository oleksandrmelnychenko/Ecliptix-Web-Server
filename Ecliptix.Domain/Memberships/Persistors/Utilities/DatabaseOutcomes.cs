namespace Ecliptix.Domain.Memberships.Persistors.Utilities;

internal static class DatabaseOutcomes
{
    public const string PhoneNotFound = "phone_not_found";
    public const string ExistingSessionReusedAndUpdated = "existing_session_reused_and_updated";
    public const string Created = "created";
    public const string ConflictResolvedToExisting = "conflict_resolved_to_existing";
    public const string ConflictUnresolved = "conflict_unresolved";

    public const string SessionNotFoundOrInvalid = "session_not_found_or_invalid";
    public const string MaxOtpAttemptsReached = "max_otp_attempts_reached";

    public const string InvalidAppDeviceId = "invalid_app_device_id";
    public const string CreatedButInvalidAppDeviceId = "created_but_invalid_app_device_id";
    
    public const string Success = "success";
    public const string MembershipNotFound = "membership_not_found";
    public const string PhoneNumberNotFound = "phone_number_not_found";
    public const string InvalidSecureKey = "invalid_secure_key";
    public const string InactiveMembership = "inactive_membership";
    public const string PhoneNumberCannotBeEmpty = "phone_number_cannot_be_empty";
    public const string SecureKeyCannotBeEmpty = "secure_key_cannot_be_empty";
    public const string SecureKeyTooLong = "secure_key_too_long";
    public const string VerificationSessionNotFound = "verification_session_not_found";
    public const string VerificationSessionNotVerified = "verification_session_not_verified";
    public const string OtpNotVerified = "otp_not_verified";
    public const string MembershipAlreadyExists = "membership_already_exists";
}