namespace Ecliptix.Domain.AppDevices.Failures;

public enum AppDeviceFailureType
{
    RegistrationFailed,
    DeviceUpdateFailed,
    PersistorAccess,
    ConcurrencyConflict,
    Validation,
    SecurityViolation,
    Generic
}