using Ecliptix.Domain.AppDevices;
using Ecliptix.Domain.AppDevices.Failures;
using Ecliptix.Domain.Memberships.Failures;
using Grpc.Core;

namespace Ecliptix.Domain.Utilities;

public static class FailureExtensions
{
    /// <summary>
    /// Converts VerificationFlowFailure to gRPC Status.
    /// User-facing errors use the actual message key, system errors use generic messages.
    /// </summary>
    public static Status ToGrpcStatus(this VerificationFlowFailure failure)
    {
        if (failure.IsUserFacing)
        {
        }

        if (failure.IsRecoverable)
        {
        }

        if (failure.IsSecurityRelated)
        {
        }

        return failure.FailureType switch
        {
            VerificationFlowFailureType.NotFound => new Status(StatusCode.NotFound,
                VerificationFlowMessageKeys.SessionNotFound),
            VerificationFlowFailureType.Expired => new Status(StatusCode.DeadlineExceeded,
                VerificationFlowMessageKeys.SessionExpired),
            VerificationFlowFailureType.InvalidOtp => new Status(StatusCode.InvalidArgument,
                VerificationFlowMessageKeys.InvalidOtp),
            VerificationFlowFailureType.OtpExpired => new Status(StatusCode.DeadlineExceeded,
                VerificationFlowMessageKeys.OtpExpired),
            VerificationFlowFailureType.OtpMaxAttemptsReached => new Status(StatusCode.ResourceExhausted,
                VerificationFlowMessageKeys.OtpMaxAttemptsReached),
            VerificationFlowFailureType.PhoneNumberInvalid => new Status(StatusCode.InvalidArgument,
                VerificationFlowMessageKeys.PhoneNumberInvalid),
            VerificationFlowFailureType.RateLimitExceeded => new Status(StatusCode.ResourceExhausted,
                VerificationFlowMessageKeys.RateLimitExceeded),
            VerificationFlowFailureType.Validation => new Status(StatusCode.InvalidArgument,
                VerificationFlowMessageKeys.Validation),

            VerificationFlowFailureType.SmsSendFailed => new Status(StatusCode.Unavailable,
                VerificationFlowMessageKeys.SmsSendFailed),

            VerificationFlowFailureType.Conflict => new Status(StatusCode.Internal,
                ErrorMessages.ConflictOccurred),
            VerificationFlowFailureType.OtpGenerationFailed => new Status(StatusCode.Internal,
                ErrorMessages.ServiceTemporarilyUnavailable),
            VerificationFlowFailureType.PersistorAccess => new Status(StatusCode.Internal,
                ErrorMessages.ServiceTemporarilyUnavailable),
            VerificationFlowFailureType.ConcurrencyConflict => new Status(StatusCode.Internal,
                ErrorMessages.PleaseTryAgain),
            VerificationFlowFailureType.SuspiciousActivity => new Status(StatusCode.PermissionDenied,
                ErrorMessages.RequestBlockedForSecurity),

            _ => new Status(StatusCode.Internal, ErrorMessages.InternalServerError)
        };
    }

    /// <summary>
    /// Converts AppDeviceFailure to gRPC Status.
    /// User-facing errors use the actual message key, system errors use generic messages.
    /// </summary>
    public static Status ToGrpcStatus(this AppDeviceFailure failure)
    {
        return failure.Type switch
        {
            AppDeviceFailureType.RegistrationFailed => new Status(StatusCode.Internal,
                ErrorMessages.DeviceRegistrationFailed),
            AppDeviceFailureType.DeviceUpdateFailed => new Status(StatusCode.Internal,
                ErrorMessages.DeviceUpdateFailed),
            AppDeviceFailureType.PersistorAccess => new Status(StatusCode.Internal,
                ErrorMessages.ServiceTemporarilyUnavailable),
            AppDeviceFailureType.ConcurrencyConflict => new Status(StatusCode.Internal,
                ErrorMessages.PleaseTryAgain),
            AppDeviceFailureType.SecurityViolation => new Status(StatusCode.PermissionDenied,
                ErrorMessages.RequestBlockedForSecurity),

            _ => new Status(StatusCode.Internal, ErrorMessages.InternalServerError)
        };
    }

    /// <summary>
    /// Converts EcliptixProtocolFailure to gRPC Status.
    /// All protocol errors are considered system errors and use generic messages.
    /// </summary>
    public static Status ToGrpcStatus(this EcliptixProtocolFailure failure)
    {
        StatusCode code = failure.FailureType switch
        {
            EcliptixProtocolFailureType.InvalidInput => StatusCode.InvalidArgument,
            EcliptixProtocolFailureType.ObjectDisposed => StatusCode.FailedPrecondition,
            EcliptixProtocolFailureType.EphemeralMissing => StatusCode.FailedPrecondition,
            EcliptixProtocolFailureType.StateMissing => StatusCode.FailedPrecondition,
            EcliptixProtocolFailureType.AllocationFailed => StatusCode.ResourceExhausted,
            EcliptixProtocolFailureType.DataTooLarge => StatusCode.InvalidArgument,
            EcliptixProtocolFailureType.BufferTooSmall => StatusCode.Internal,
            EcliptixProtocolFailureType.MemoryBufferError => StatusCode.Internal,
            EcliptixProtocolFailureType.DecryptFailed => StatusCode.Unauthenticated,
            EcliptixProtocolFailureType.EncryptionFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.KeyGenerationFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.DeriveKeyFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.HandshakeFailed => StatusCode.Unauthenticated,
            EcliptixProtocolFailureType.PinningFailure => StatusCode.Internal,
            EcliptixProtocolFailureType.ConversionFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.PrepareLocalFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.PeerPubKeyFailed => StatusCode.Unauthenticated,
            EcliptixProtocolFailureType.PeerExchangeFailed => StatusCode.Unauthenticated,
            EcliptixProtocolFailureType.KeyRotationFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.StoreOpFailed => StatusCode.Internal,
            EcliptixProtocolFailureType.InvalidKeySize => StatusCode.InvalidArgument,
            EcliptixProtocolFailureType.InvalidEd25519Key => StatusCode.InvalidArgument,
            EcliptixProtocolFailureType.SpkVerificationFailed => StatusCode.Unauthenticated,
            EcliptixProtocolFailureType.HkdfInfoEmpty => StatusCode.InvalidArgument,
            _ => StatusCode.Internal
        };

        string message = code switch
        {
            StatusCode.InvalidArgument => ErrorMessages.InvalidRequest,
            StatusCode.FailedPrecondition => ErrorMessages.InvalidRequest,
            StatusCode.ResourceExhausted => ErrorMessages.ServiceTemporarilyUnavailable,
            StatusCode.Unauthenticated => ErrorMessages.AuthenticationFailed,
            _ => ErrorMessages.InternalServerError
        };

        return new Status(code, message);
    }
}

/// <summary>
/// Static class containing generic error messages for system errors.
/// These are not localization keys and are used directly for security reasons.
/// </summary>
internal static class ErrorMessages
{
    public const string ConflictOccurred = "A conflict occurred, please try again";
    public const string ServiceTemporarilyUnavailable = "Service temporarily unavailable";
    public const string PleaseTryAgain = "Please try again";
    public const string RequestBlockedForSecurity = "Request blocked for security reasons";
    public const string InternalServerError = "Internal server error";
    public const string DeviceRegistrationFailed = "Device registration failed";
    public const string DeviceUpdateFailed = "Device update failed";
    public const string InvalidRequest = "Invalid request";
    public const string AuthenticationFailed = "Authentication failed";
}