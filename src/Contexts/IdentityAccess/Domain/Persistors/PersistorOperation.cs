namespace Ecliptix.IdentityAccess.Domain.Persistors;

/// <summary>
/// Defines all persistor operations for type-safe operation naming,
/// timeout configuration, and logging/tracing.
/// </summary>
public enum PersistorOperation
{
    // Membership operations
    CreateMembership,
    LoginMembership,
    SignInMembership,
    GetMembershipByVerificationFlow,
    GetMembershipByUniqueId,
    UpdateMembershipVerificationFlow,
    UpdateMembershipCreationStatus,

    // Account operations
    CreateDefaultAccount,
    UpdateAccountSecureKey,
    EnsureAccountMaskingKey,
    GetDefaultAccountId,
    GetAccountsByMembershipId,

    // Account profile operations
    GetAccountProfile,
    UpdateAccountProfile,
    CheckProfileNameAvailability,

    // Verification flow operations
    InitiateVerificationFlow,
    CreateVerificationFlow,
    UpdateVerificationFlowStatus,
    GetVerificationFlow,
    RequestResendOtp,
    QueryFlowStatusByConnectionId,

    // OTP operations
    CreateOtp,
    UpdateOtpStatus,
    GetOtp,
    GetOtpAttemptCount,
    IncrementOtpAttemptCount,
    LogFailedAttempt,

    // Mobile number operations
    EnsureMobileNumber,
    GetMobileNumber,
    CheckMobileNumberAvailability,
    VerifyMobileForSecretKeyRecovery,
    CheckExistingMembership,

    // Password recovery operations
    ValidatePasswordRecoveryFlow,
    ExpirePasswordRecoveryFlows,

    // Logout operations
    RecordLogout,
    GetLogoutHistory,
    GetMostRecentLogout,
    GetLogoutByDevice,

    // Master key operations
    InsertMasterKeyShares,
    GetMasterKeyShares,
    DeleteMasterKeyShares,

    // Device operations
    RegisterAppDevice
}
