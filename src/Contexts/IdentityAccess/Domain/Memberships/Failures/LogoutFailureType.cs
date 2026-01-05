namespace Ecliptix.IdentityAccess.Domain.Memberships.Failures;

public enum LogoutFailureType : short
{
    RecordFailed,
    NotFound,
    QueryFailed,
    ValidationFailed,
    PersistorAccess,
    InternalError
}
