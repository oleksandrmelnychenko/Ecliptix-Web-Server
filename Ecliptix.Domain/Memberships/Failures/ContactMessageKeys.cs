namespace Ecliptix.Domain.Memberships.Failures;

public static class ContactMessageKeys
{
    public const string ContactNotFound = "contact_not_found";
    public const string ContactRelationNotFound = "contact_relation_not_found";

    public const string AlreadyContact = "already_contact";

    public const string UserBlocked = "user_blocked";
    public const string BlockedByUser = "blocked_by_user";

    public const string CannotAddYourself = "cannot_add_yourself";
    public const string NotInContacts = "not_in_contacts";

    public const string ValidationFailed = "contact_validation_failed";
    public const string InvalidMembershipId = "invalid_membership_id";

    public const string DataAccess = "contact_data_access_failed";
    public const string RemoveContactFailed = "remove_contact_failed";
    public const string ListContactsFailed = "list_contacts_failed";
    public const string GetContactStatusFailed = "get_contact_status_failed";
    public const string BlockContactFailed = "block_contact_failed";
    public const string UnblockContactFailed = "unblock_contact_failed";
    public const string MuteContactFailed = "mute_contact_failed";
    public const string UnmuteContactFailed = "unmute_contact_failed";

    public const string ConcurrencyConflict = "contact_concurrency_conflict";

    public const string Generic = "contact_generic_error";
    public const string UnexpectedError = "contact_unexpected_error";
}
