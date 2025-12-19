namespace Ecliptix.Domain.Memberships.Failures;

public enum AccountProfileFailureType
{
    None = 0,
    NotFound = 1,
    AlreadyExists = 2,
    ValidationFailed = 3,
    PersistorAccess = 4,
    InternalError = 5
}
