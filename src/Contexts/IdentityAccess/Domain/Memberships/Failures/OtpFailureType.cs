namespace Ecliptix.IdentityAccess.Domain.Memberships.Failures;

public enum OtpFailureType : short
{
    NotFound,
    Invalid,
    Expired,
    MaxAttemptsReached,
    GenerationFailed,
    AlreadyUsed,
    ValidationFailed,
    UpdateFailed,
    PersistorAccess,
    InternalError
}
