namespace Ecliptix.Domain.Memberships.Failures;

public enum MembershipFailureType : short
{
    NotFound,
    AlreadyExists,
    CreationFailed,
    UpdateFailed,
    StatusUpdateFailed,
    ValidationFailed,
    InvalidStatus,
    PersistorAccess,
    InternalError
}
