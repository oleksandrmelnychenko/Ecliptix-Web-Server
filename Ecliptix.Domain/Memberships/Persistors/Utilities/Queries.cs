namespace Ecliptix.Domain.Memberships.Persistors.Utilities;

internal static class Queries
{
    public const string GetVerificationFlow =
        "SELECT session_unique_id, phone_number_unique_id_out, connection_id, app_device_id_out, phone_number_out, " +
        "phone_region_out, expires_at_out, status_out, purpose_out, otp_count_out, otp_unique_id, " +
        "otp_hash, otp_salt, otp_expires_at, otp_status FROM get_verification_session(@app_device_id, @phone_unique_id, @purpose::verification_purpose)";

    public const string CreateVerificationFlow =
        "SELECT session_unique_id, outcome FROM create_verification_session(@app_device_id, @phone_unique_id, @purpose::verification_purpose, @expires_at, @connect_id)";

    public const string UpdateSessionStatus =
        "SELECT update_verification_session_status(@session_unique_id, @status::verification_status)";

    public const string UpdateOtpStatus =
        "SELECT success, message FROM update_otp_status(@otp_unique_id, @status::verification_status)";

    public const string GetPhoneNumber = @"
            SELECT phone_number, region
            FROM get_phone_number(@phone_unique_id);
        ";

    public const string CreateOtp = @"
            SELECT otp_unique_id, outcome FROM insert_otp_record(@session_unique_id, @otp_hash, @otp_salt, @expires_at, @status::verification_status)";

    public const string EnsurePhoneNumber =
        "SELECT unique_id, outcome, success, message FROM ensure_phone_number(@phone_number_string, @region)";
    
    public const string LoginMembership = @"
            SELECT membership_unique_id, status, outcome 
            FROM login_membership(@phone_number, @secure_key)";

    public const string UpdateMembershipSecureKey = @"
            SELECT success, message, membership_unique_id, status, creation_status
            FROM update_membership_secure_key(@membership_unique_id, @secure_key)";

    public const string CreateMembership = @"
            SELECT membership_unique_id, status, creation_status, outcome
            FROM create_membership(@session_unique_id, @connection_id, @otp_unique_id, @creation_status::membership_creation_status)";
}