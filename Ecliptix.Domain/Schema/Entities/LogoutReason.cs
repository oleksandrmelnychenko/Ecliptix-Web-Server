namespace Ecliptix.Domain.Schema.Entities;

public enum LogoutReason
{
    UserInitiated,
    DeviceRemoved,
    SecurityViolation,
    AccountDeactivated,
    PasswordChanged,
    ForceLogout,
    SystemMaintenance
}
