namespace Ecliptix.Domain.Memberships.Failures;

public enum FriendFailureType : short
{
    NotFound,
    AlreadyRequested,
    AlreadyFriends,
    Blocked,
    
    InvalidRequest,
    Validation,
    
    PersistorAccess,
    ConcurrencyConflict,
    DatabaseError,
    
    Unauthorized,
    
    Generic
}

