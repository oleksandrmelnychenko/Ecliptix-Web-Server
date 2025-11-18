namespace Ecliptix.Domain.Memberships.Failures;

public enum FriendFailureType
{
    NotFound,
    ValidationFailed,
    AlreadyRequested,
    AlreadyFriends,
    Blocked,
    PersistorAccess,
    UnexpectedError
}