namespace Ecliptix.Domain.Memberships.Failures;

public static class FriendMessageKeys
{
    public const string FriendNotFound = "friend_not_found";
    public const string FriendRelationNotFound = "friend_relation_not_found";
    public const string FriendRequestNotFound = "friend_request_not_found";
    
    public const string AlreadyRequested = "friend_already_requested";
    public const string AlreadyFriends = "already_friends";

    public const string UserBlocked = "user_blocked";
    public const string BlockedByUser = "blocked_by_user";
    
    public const string CannotFriendYourself = "cannot_friend_yourself";
    public const string CannotAcceptOwnRequest = "cannot_accept_own_request";
    public const string CannotCancelOtherRequest = "cannot_cancel_other_request";
    public const string RequestNotPending = "request_not_pending";
    public const string NotFriends = "not_friends";
    
    public const string ValidationFailed = "friend_validation_failed";
    public const string InvalidMembershipId = "invalid_membership_id";
    
    public const string DataAccess = "friend_data_access_failed";
    public const string SendRequestFailed = "send_friend_request_failed";
    public const string AcceptRequestFailed = "accept_friend_request_failed";
    public const string RejectRequestFailed = "reject_friend_request_failed";
    public const string CancelRequestFailed = "cancel_friend_request_failed";
    public const string RemoveFriendFailed = "remove_friend_failed";
    public const string ListFriendsFailed = "list_friends_failed";
    public const string GetFriendshipStatusFailed = "get_friendship_status_failed";
    
    public const string ConcurrencyConflict = "friend_concurrency_conflict";
    
    public const string Generic = "friend_generic_error";
    public const string UnexpectedError = "friend_unexpected_error";
}