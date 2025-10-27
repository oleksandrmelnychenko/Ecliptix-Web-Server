namespace Ecliptix.Domain.Memberships.Failures;

public static class LogoutMessageKeys
{
    public const string AuditRecordFailed = "logout_audit_record_failed";

    public const string QueryFailed = "logout_query_failed";
    public const string HistoryQueryFailed = "logout_history_query_failed";
    public const string MostRecentQueryFailed = "logout_most_recent_query_failed";
    public const string DeviceQueryFailed = "logout_device_query_failed";

    public const string LogoutNotFound = "logout_not_found";
    public const string LogoutHistoryNotFound = "logout_history_not_found";
    public const string LogoutByDeviceNotFound = "logout_by_device_not_found";

    public const string MembershipIdInvalid = "logout_membership_id_invalid";
    public const string DeviceIdInvalid = "logout_device_id_invalid";
    public const string ReasonInvalid = "logout_reason_invalid";

    public const string DataAccess = "logout_data_access_failed";
    public const string DatabaseError = "logout_database_error";
    public const string Timeout = "logout_operation_timeout";

    public const string Generic = "logout_error_generic";
}
