namespace Ecliptix.DeviceProvisioning.Domain.Failures;

public static class AppDeviceMessageKeys
{
    public const string DataAccess = "appdevice_error_infrastructure";

    public const string Generic = "appdevice_error_internal";

    public const string RegistrationInvalidRequest = "appdevice_registration_invalid_request";
    public const string RegistrationAlreadyExists = "appdevice_registration_already_exists";
    public const string RegistrationSuccess = "appdevice_registration_success";
}
