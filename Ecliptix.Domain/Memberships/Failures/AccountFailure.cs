using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record AccountFailure(
    AccountFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        AccountFailureType.PersistorAccess => true,
        AccountFailureType.CreationFailed => true,
        AccountFailureType.CredentialUpdateFailed => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        AccountFailureType.NotFound => true,
        AccountFailureType.AlreadyExists => true,
        AccountFailureType.ValidationFailed => true,
        _ => false
    };

    public static AccountFailure NotFoundById(string? details = null)
    {
        return new AccountFailure(AccountFailureType.NotFound,
            details ?? AccountMessageKeys.AccountNotFoundById);
    }

    public static AccountFailure NotFoundByMembership(string? details = null)
    {
        return new AccountFailure(AccountFailureType.NotFound,
            details ?? AccountMessageKeys.AccountNotFoundByMembership);
    }

    public static AccountFailure AlreadyExists(string? details = null)
    {
        return new AccountFailure(AccountFailureType.AlreadyExists,
            details ?? AccountMessageKeys.AccountAlreadyExists);
    }

    public static AccountFailure CreationFailed(Exception? ex = null)
    {
        return new AccountFailure(AccountFailureType.CreationFailed,
            AccountMessageKeys.CreateAccountFailed, ex);
    }

    public static AccountFailure CredentialUpdateFailed(Exception? ex = null)
    {
        return new AccountFailure(AccountFailureType.CredentialUpdateFailed,
            AccountMessageKeys.CredentialUpdateFailed, ex);
    }

    public static AccountFailure ValidationFailed(string? details = null)
    {
        return new AccountFailure(AccountFailureType.ValidationFailed,
            details ?? AccountMessageKeys.ValidationFailed);
    }

    public static AccountFailure DatabaseError(Exception? ex = null)
    {
        return new AccountFailure(AccountFailureType.PersistorAccess,
            AccountMessageKeys.DatabaseError, ex);
    }

    public static AccountFailure Timeout(Exception? ex = null)
    {
        return new AccountFailure(AccountFailureType.PersistorAccess,
            AccountMessageKeys.Timeout, ex);
    }

    public static AccountFailure QueryFailed(Exception? ex = null)
    {
        return new AccountFailure(AccountFailureType.PersistorAccess,
            AccountMessageKeys.QueryFailed, ex);
    }

    public static AccountFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new AccountFailure(AccountFailureType.InternalError,
            details ?? AccountMessageKeys.Generic, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            AccountFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            AccountFailureType.AlreadyExists => new GrpcErrorDescriptor(
                ErrorCode.AlreadyExists,
                StatusCode.AlreadyExists,
                i18NKey),
            AccountFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            AccountFailureType.CreationFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            AccountFailureType.CredentialUpdateFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            AccountFailureType.PersistorAccess => new GrpcErrorDescriptor(
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

    private static string GetDefaultI18NKey(AccountFailureType failureType) =>
        failureType switch
        {
            AccountFailureType.NotFound => ErrorI18NKeys.NotFound,
            AccountFailureType.AlreadyExists => ErrorI18NKeys.AlreadyExists,
            AccountFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            AccountFailureType.CreationFailed => ErrorI18NKeys.DatabaseUnavailable,
            AccountFailureType.CredentialUpdateFailed => ErrorI18NKeys.DatabaseUnavailable,
            AccountFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
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
