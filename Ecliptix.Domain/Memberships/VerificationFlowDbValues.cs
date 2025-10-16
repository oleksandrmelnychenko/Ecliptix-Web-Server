using Ecliptix.Domain.Status;

namespace Ecliptix.Domain.Memberships;

internal static class VerificationFlowDbValues
{
    internal const string StatusPending = StatusCatalog.VerificationFlow.Pending;
    internal const string StatusVerified = StatusCatalog.VerificationFlow.Verified;
    internal const string StatusExpired = StatusCatalog.VerificationFlow.Expired;

    internal const string OtpStatusActive = StatusCatalog.Otp.Active;
    internal const string OtpStatusInvalid = StatusCatalog.Otp.Invalid;
    internal const string OtpStatusExpired = StatusCatalog.Otp.Expired;
    internal const string OtpStatusUsed = StatusCatalog.Otp.Used;

    internal const string PurposeUnspecified = StatusCatalog.VerificationPurpose.Unspecified;
    internal const string PurposeRegistration = StatusCatalog.VerificationPurpose.Registration;
    internal const string PurposeLogin = StatusCatalog.VerificationPurpose.Login;
    internal const string PurposePasswordRecovery = StatusCatalog.VerificationPurpose.PasswordRecovery;
    internal const string PurposeUpdatePhone = StatusCatalog.VerificationPurpose.UpdatePhone;

    internal const string OutcomeCreated = "created";
    internal const string OutcomeIdempotent = "idempotent";

    internal const string MobileAvailabilityTaken = "taken";
    internal const string MobileAvailabilityAvailable = "available";
}
