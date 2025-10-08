namespace Ecliptix.Domain.Schema.Entities;

public enum LogoutReason
{
    UserInitiated,
    SessionExpired,
    SessionTimeout,
    DeviceRemoved,
    SecurityViolation,
    AccountDeactivated,
    PasswordChanged,
    ForceLogout,
    SystemMaintenance
}
