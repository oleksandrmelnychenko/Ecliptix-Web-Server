namespace Ecliptix.Domain.Memberships.Failures;

public enum AccountFailureType : short
{
    NotFound,
    AlreadyExists,
    CreationFailed,
    CredentialUpdateFailed,
    ValidationFailed,
    PersistorAccess,
    InternalError
}
