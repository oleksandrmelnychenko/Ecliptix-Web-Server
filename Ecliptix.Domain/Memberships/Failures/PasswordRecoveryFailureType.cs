namespace Ecliptix.Domain.Memberships.Failures;

public enum PasswordRecoveryFailureType : short
{
    TokenNotFound,
    TokenExpired,
    TokenInvalid,
    TokenAlreadyUsed,
    InitiationFailed,
    ResetFailed,
    ValidationFailed,
    PersistorAccess,
    InternalError
}
