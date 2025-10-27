using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record PasswordRecoveryFailure(
    PasswordRecoveryFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        PasswordRecoveryFailureType.PersistorAccess => true,
        PasswordRecoveryFailureType.InitiationFailed => true,
        PasswordRecoveryFailureType.ResetFailed => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        PasswordRecoveryFailureType.TokenNotFound => true,
        PasswordRecoveryFailureType.TokenExpired => true,
        PasswordRecoveryFailureType.TokenInvalid => true,
        PasswordRecoveryFailureType.TokenAlreadyUsed => true,
        PasswordRecoveryFailureType.ValidationFailed => true,
        _ => false
    };

    public static PasswordRecoveryFailure TokenExpired(string? details = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.TokenExpired,
            details ?? PasswordRecoveryMessageKeys.TokenExpired);
    }

    public static PasswordRecoveryFailure TokenInvalid(string? details = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.TokenInvalid,
            details ?? PasswordRecoveryMessageKeys.TokenInvalid);
    }

    public static PasswordRecoveryFailure ResetFailed(string? details = null, Exception? ex = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.ResetFailed,
            details ?? PasswordRecoveryMessageKeys.ResetFailed, ex);
    }

    public static PasswordRecoveryFailure VerificationFailed(string? details = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.TokenInvalid,
            details ?? PasswordRecoveryMessageKeys.VerificationFailed);
    }

    public static PasswordRecoveryFailure ValidationFailed(string? details = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.ValidationFailed,
            details ?? PasswordRecoveryMessageKeys.ValidationFailed);
    }

    public static PasswordRecoveryFailure PersistorAccess(string? details = null, Exception? ex = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.PersistorAccess,
            details ?? PasswordRecoveryMessageKeys.DataAccess, ex);
    }

    public static PasswordRecoveryFailure DatabaseError(Exception? ex = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.PersistorAccess,
            PasswordRecoveryMessageKeys.DatabaseError, ex);
    }

    public static PasswordRecoveryFailure Timeout(Exception? ex = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.PersistorAccess,
            PasswordRecoveryMessageKeys.Timeout, ex);
    }

    public static PasswordRecoveryFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new PasswordRecoveryFailure(PasswordRecoveryFailureType.InternalError,
            details ?? PasswordRecoveryMessageKeys.Generic, ex);
    }

    public static PasswordRecoveryFailure FromAccount(AccountFailure accountFailure)
    {
        return accountFailure.FailureType switch
        {
            AccountFailureType.NotFound => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.AlreadyExists => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.ValidationFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.CreationFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.CredentialUpdateFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.PersistorAccess => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.PersistorAccess,
                accountFailure.Message,
                accountFailure.InnerException),

            _ => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.InternalError,
                accountFailure.Message,
                accountFailure.InnerException)
        };
    }

    public static PasswordRecoveryFailure FromMasterKey(MasterKeyFailure masterKeyFailure)
    {
        return masterKeyFailure.FailureType switch
        {
            MasterKeyFailureType.InvalidThreshold => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidShareCount => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidKeyLength => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidKeyData => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidShareData => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidIdentifier => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.KeySplittingFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.KeyReconstructionFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.ShareValidationFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InsufficientShares => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.TokenNotFound,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyStorageFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyMissing => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.TokenNotFound,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyRetrievalFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyRemovalFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.KeyDerivationFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.AllocationFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.MemoryReadFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.MemoryWriteFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.ValidationFailed => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.PersistorAccess => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.PersistorAccess,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            _ => new PasswordRecoveryFailure(
                PasswordRecoveryFailureType.InternalError,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException)
        };
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            PasswordRecoveryFailureType.TokenNotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            PasswordRecoveryFailureType.TokenExpired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18NKey),
            PasswordRecoveryFailureType.TokenInvalid => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            PasswordRecoveryFailureType.TokenAlreadyUsed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            PasswordRecoveryFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            PasswordRecoveryFailureType.InitiationFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            PasswordRecoveryFailureType.ResetFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            PasswordRecoveryFailureType.PersistorAccess => new GrpcErrorDescriptor(
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

    private static string GetDefaultI18NKey(PasswordRecoveryFailureType failureType) =>
        failureType switch
        {
            PasswordRecoveryFailureType.TokenNotFound => ErrorI18NKeys.NotFound,
            PasswordRecoveryFailureType.TokenExpired => ErrorI18NKeys.OtpExpired,
            PasswordRecoveryFailureType.TokenInvalid => ErrorI18NKeys.Unauthenticated,
            PasswordRecoveryFailureType.TokenAlreadyUsed => ErrorI18NKeys.Validation,
            PasswordRecoveryFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            PasswordRecoveryFailureType.InitiationFailed => ErrorI18NKeys.ServiceUnavailable,
            PasswordRecoveryFailureType.ResetFailed => ErrorI18NKeys.DatabaseUnavailable,
            PasswordRecoveryFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
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
