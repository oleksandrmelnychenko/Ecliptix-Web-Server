namespace Ecliptix.IdentityAccess.Domain.Memberships.Otp;

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
