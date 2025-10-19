namespace Ecliptix.Utilities;

public enum ErrorCode
{
    ValidationFailed = 0,
    MaxAttemptsReached = 1,
    InvalidMobileNumber = 2,
    OtpExpired = 3,
    NotFound = 4,
    AlreadyExists = 5,
    Unauthenticated = 6,
    PermissionDenied = 7,
    PreconditionFailed = 8,
    Conflict = 9,
    ResourceExhausted = 10,
    ServiceUnavailable = 11,
    DependencyUnavailable = 12,
    DeadlineExceeded = 13,
    Cancelled = 14,
    InternalError = 15,
    DatabaseUnavailable = 16
}
