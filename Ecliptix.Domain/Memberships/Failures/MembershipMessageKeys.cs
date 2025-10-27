namespace Ecliptix.Domain.Memberships.Failures;

public static class MembershipMessageKeys
{
    // Membership queries
    public const string MembershipNotFound = "membership_not_found";
    public const string MembershipNotFoundById = "membership_not_found_by_id";
    public const string MembershipNotFoundByMobile = "membership_not_found_by_mobile";
    public const string MembershipNotFoundForUpdate = "membership_not_found_for_update";

    // Membership existence
    public const string MembershipAlreadyExists = "membership_already_exists";
    public const string MembershipExistsForMobile = "membership_exists_for_mobile";
    public const string MembershipExistsIncomplete = "membership_exists_incomplete";

    // Membership operations
    public const string CreateMembershipFailed = "create_membership_failed";
    public const string UpdateMembershipFailed = "update_membership_failed";
    public const string UpdateStatusFailed = "update_membership_status_failed";
    public const string CheckExistenceFailed = "check_membership_existence_failed";
    public const string EnsureMembershipFailed = "ensure_membership_failed";

    // Status validation
    public const string InvalidStatus = "membership_invalid_status";
    public const string InvalidStatusTransition = "membership_invalid_status_transition";
    public const string StatusMismatch = "membership_status_mismatch";

    // Validation
    public const string ValidationFailed = "membership_validation_failed";
    public const string InvalidMembershipData = "membership_invalid_data";

    // Infrastructure
    public const string DataAccess = "membership_data_access_failed";
    public const string DatabaseError = "membership_database_error";
    public const string Timeout = "membership_operation_timeout";
    public const string QueryFailed = "membership_query_failed";

    // Generic
    public const string Generic = "membership_error_generic";
}
