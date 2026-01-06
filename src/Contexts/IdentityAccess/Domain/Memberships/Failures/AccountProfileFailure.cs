using Ecliptix.SharedKernel;
using Grpc.Core;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Failures;

public sealed record AccountProfileFailure(AccountProfileFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        AccountProfileFailureType.PersistorAccess => true,
        _ => false
    };

    public override bool IsUserFacing => FailureType switch
    {
        AccountProfileFailureType.NotFound => true,
        AccountProfileFailureType.AlreadyExists => true,
        AccountProfileFailureType.ValidationFailed => true,
        _ => false
    };

    public override bool Retryable => FailureType switch
    {
        AccountProfileFailureType.PersistorAccess => true,
        _ => false
    };

    public override ErrorSurface Surface => FailureType switch
    {
        AccountProfileFailureType.PersistorAccess or AccountProfileFailureType.InternalError => ErrorSurface.System,
        _ => ErrorSurface.User
    };

    public override string PublicErrorCode => FailureType switch
    {
        AccountProfileFailureType.NotFound => "account_profile.not_found",
        AccountProfileFailureType.AlreadyExists => "account_profile.already_exists",
        AccountProfileFailureType.ValidationFailed => "account_profile.validation_failed",
        AccountProfileFailureType.PersistorAccess => "account_profile.persistence",
        _ => "account_profile.internal"
    };

    public override string? UserMessageKey => GetDefaultI18NKey(FailureType);

    public static AccountProfileFailure NotFound(string? details = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.NotFound,
            details ?? AccountProfileMessageKeys.ProfileNotFound);
    }

    public static AccountProfileFailure AlreadyExists(string? details = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.AlreadyExists,
            details ?? AccountProfileMessageKeys.ProfileAlreadyExists);
    }

    public static AccountProfileFailure QueryFailed(Exception? ex = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.PersistorAccess,
            AccountProfileMessageKeys.QueryFailed, ex);
    }

    public static AccountProfileFailure ValidationFailed(string? details = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.ValidationFailed,
            details ?? AccountProfileMessageKeys.ValidationFailed);
    }

    public static AccountProfileFailure DatabaseError(Exception? ex = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.PersistorAccess,
            AccountProfileMessageKeys.DatabaseError, ex);
    }

    public static AccountProfileFailure Timeout(Exception? ex = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.PersistorAccess,
            AccountProfileMessageKeys.Timeout, ex);
    }

    public static AccountProfileFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new AccountProfileFailure(AccountProfileFailureType.InternalError,
            details ?? AccountProfileMessageKeys.Generic, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(UserMessageKey) ? GetDefaultI18NKey(FailureType) : UserMessageKey!;

        return FailureType switch
        {
            AccountProfileFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),

            AccountProfileFailureType.AlreadyExists => new GrpcErrorDescriptor(
                ErrorCode.AlreadyExists,
                StatusCode.AlreadyExists,
                i18NKey),

            AccountProfileFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),

            AccountProfileFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),

            _ => new GrpcErrorDescriptor(
                ErrorCode.InternalError,
                StatusCode.Internal,
                i18NKey)
        };
    }

    private static string GetDefaultI18NKey(AccountProfileFailureType failureType) =>
        failureType switch
        {
            AccountProfileFailureType.NotFound => ErrorI18NKeys.NotFound,
            AccountProfileFailureType.AlreadyExists => ErrorI18NKeys.AlreadyExists,
            AccountProfileFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            AccountProfileFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
            _ => ErrorI18NKeys.Internal
        };

    public override object ToStructuredLog()
    {
        return new
        {
            Domain = "AccountProfile",
            FailureType = FailureType.ToString(),
            Message,
            InnerException,
            Timestamp,
            IsRecoverable,
            IsUserFacing,
            Retryable,
            Surface = Surface.ToString(),
            PublicErrorCode
        };
    }
}
