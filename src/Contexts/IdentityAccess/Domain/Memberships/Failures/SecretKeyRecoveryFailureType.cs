namespace Ecliptix.IdentityAccess.Domain.Memberships.Failures;

public enum SecretKeyRecoveryFailureType : short
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
