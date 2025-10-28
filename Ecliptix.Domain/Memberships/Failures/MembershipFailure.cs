using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record MembershipFailure(
    MembershipFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        MembershipFailureType.PersistorAccess => true,
        MembershipFailureType.CreationFailed => true,
        MembershipFailureType.UpdateFailed => true,
        MembershipFailureType.StatusUpdateFailed => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        MembershipFailureType.NotFound => true,
        MembershipFailureType.AlreadyExists => true,
        MembershipFailureType.ValidationFailed => true,
        MembershipFailureType.InvalidStatus => true,
        _ => false
    };

    public static MembershipFailure NotFound(string? details = null)
    {
        return new MembershipFailure(MembershipFailureType.NotFound,
            details ?? MembershipMessageKeys.MembershipNotFound);
    }

    public static MembershipFailure NotFoundById(string? details = null)
    {
        return new MembershipFailure(MembershipFailureType.NotFound,
            details ?? MembershipMessageKeys.MembershipNotFoundById);
    }

    public static MembershipFailure NotFoundByMobile(string? details = null)
    {
        return new MembershipFailure(MembershipFailureType.NotFound,
            details ?? MembershipMessageKeys.MembershipNotFoundByMobile);
    }

    public static MembershipFailure AlreadyExists(string? details = null)
    {
        return new MembershipFailure(MembershipFailureType.AlreadyExists,
            details ?? MembershipMessageKeys.MembershipAlreadyExists);
    }

    public static MembershipFailure CreationFailed(Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.CreationFailed,
            MembershipMessageKeys.CreateMembershipFailed, ex);
    }

    public static MembershipFailure UpdateFailed(Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.UpdateFailed,
            MembershipMessageKeys.UpdateMembershipFailed, ex);
    }

    public static MembershipFailure InvalidStatus(string? details = null)
    {
        return new MembershipFailure(MembershipFailureType.InvalidStatus,
            details ?? MembershipMessageKeys.InvalidStatus);
    }

    public static MembershipFailure ValidationFailed(string? details = null)
    {
        return new MembershipFailure(MembershipFailureType.ValidationFailed,
            details ?? MembershipMessageKeys.ValidationFailed);
    }

    public static MembershipFailure PersistorAccess(string? details = null, Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.PersistorAccess,
            details ?? MembershipMessageKeys.DataAccess, ex);
    }

    public static MembershipFailure DatabaseError(Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.PersistorAccess,
            MembershipMessageKeys.DatabaseError, ex);
    }

    public static MembershipFailure Timeout(Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.PersistorAccess,
            MembershipMessageKeys.Timeout, ex);
    }

    public static MembershipFailure QueryFailed(Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.PersistorAccess,
            MembershipMessageKeys.QueryFailed, ex);
    }

    public static MembershipFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new MembershipFailure(MembershipFailureType.InternalError,
            details ?? MembershipMessageKeys.Generic, ex);
    }

    public static MembershipFailure FromLogout(LogoutFailure logoutFailure)
    {
        return logoutFailure.FailureType switch
        {
            LogoutFailureType.RecordFailed => new MembershipFailure(
                MembershipFailureType.UpdateFailed,
                logoutFailure.Message,
                logoutFailure.InnerException),

            LogoutFailureType.NotFound => new MembershipFailure(
                MembershipFailureType.NotFound,
                logoutFailure.Message,
                logoutFailure.InnerException),

            LogoutFailureType.QueryFailed => new MembershipFailure(
                MembershipFailureType.PersistorAccess,
                logoutFailure.Message,
                logoutFailure.InnerException),

            LogoutFailureType.ValidationFailed => new MembershipFailure(
                MembershipFailureType.ValidationFailed,
                logoutFailure.Message,
                logoutFailure.InnerException),

            LogoutFailureType.PersistorAccess => new MembershipFailure(
                MembershipFailureType.PersistorAccess,
                logoutFailure.Message,
                logoutFailure.InnerException),

            LogoutFailureType.InternalError => new MembershipFailure(
                MembershipFailureType.InternalError,
                logoutFailure.Message,
                logoutFailure.InnerException),

            _ => new MembershipFailure(
                MembershipFailureType.InternalError,
                logoutFailure.Message,
                logoutFailure.InnerException)
        };
    }

    public static MembershipFailure FromAccount(AccountFailure accountFailure)
    {
        return accountFailure.FailureType switch
        {
            AccountFailureType.NotFound => new MembershipFailure(
                MembershipFailureType.NotFound,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.AlreadyExists => new MembershipFailure(
                MembershipFailureType.AlreadyExists,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.CreationFailed => new MembershipFailure(
                MembershipFailureType.CreationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.CredentialUpdateFailed => new MembershipFailure(
                MembershipFailureType.UpdateFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.ValidationFailed => new MembershipFailure(
                MembershipFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.PersistorAccess => new MembershipFailure(
                MembershipFailureType.PersistorAccess,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.InternalError => new MembershipFailure(
                MembershipFailureType.InternalError,
                accountFailure.Message,
                accountFailure.InnerException),

            _ => new MembershipFailure(
                MembershipFailureType.InternalError,
                accountFailure.Message,
                accountFailure.InnerException)
        };
    }

    public static MembershipFailure FromVerificationFlow(VerificationFlowFailure verificationFlowFailure)
    {
        return verificationFlowFailure.FailureType switch
        {
            VerificationFlowFailureType.NotFound => new MembershipFailure(
                MembershipFailureType.NotFound,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            VerificationFlowFailureType.Expired => new MembershipFailure(
                MembershipFailureType.ValidationFailed,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            VerificationFlowFailureType.Conflict => new MembershipFailure(
                MembershipFailureType.AlreadyExists,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            VerificationFlowFailureType.Validation => new MembershipFailure(
                MembershipFailureType.ValidationFailed,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            VerificationFlowFailureType.Unauthorized => new MembershipFailure(
                MembershipFailureType.ValidationFailed,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            VerificationFlowFailureType.PersistorAccess => new MembershipFailure(
                MembershipFailureType.PersistorAccess,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            VerificationFlowFailureType.Generic => new MembershipFailure(
                MembershipFailureType.InternalError,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException),

            _ => new MembershipFailure(
                MembershipFailureType.InternalError,
                verificationFlowFailure.Message,
                verificationFlowFailure.InnerException)
        };
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18nKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            MembershipFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18nKey),
            MembershipFailureType.AlreadyExists => new GrpcErrorDescriptor(
                ErrorCode.AlreadyExists,
                StatusCode.AlreadyExists,
                i18nKey),
            MembershipFailureType.InvalidStatus => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18nKey),
            MembershipFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18nKey),
            MembershipFailureType.CreationFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            MembershipFailureType.UpdateFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            MembershipFailureType.StatusUpdateFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            MembershipFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18nKey,
                Retryable: true),
            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18nKey)
        };
    }

    private static string GetDefaultI18NKey(MembershipFailureType failureType) =>
        failureType switch
        {
            MembershipFailureType.NotFound => ErrorI18NKeys.NotFound,
            MembershipFailureType.AlreadyExists => ErrorI18NKeys.AlreadyExists,
            MembershipFailureType.InvalidStatus => ErrorI18NKeys.Validation,
            MembershipFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            MembershipFailureType.CreationFailed => ErrorI18NKeys.DatabaseUnavailable,
            MembershipFailureType.UpdateFailed => ErrorI18NKeys.DatabaseUnavailable,
            MembershipFailureType.StatusUpdateFailed => ErrorI18NKeys.DatabaseUnavailable,
            MembershipFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
            MembershipFailureType.InternalError => ErrorI18NKeys.Internal,
            _ => ErrorI18NKeys.Internal
        };

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsRecoverable,
            IsUserFacing
        };
    }
}
