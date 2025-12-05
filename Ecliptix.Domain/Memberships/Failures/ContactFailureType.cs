namespace Ecliptix.Domain.Memberships.Failures;

public enum ContactFailureType : short
{
    NotFound,
    AlreadyContact,
    Blocked,

    InvalidRequest,
    Validation,

    PersistorAccess,
    ConcurrencyConflict,
    DatabaseError,

    Unauthorized,

    Generic
}
