using Ecliptix.SharedKernel;
using Grpc.Core;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Failures;

public sealed record SecretKeyRecoveryFailure(
    SecretKeyRecoveryFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        SecretKeyRecoveryFailureType.PersistorAccess => true,
        SecretKeyRecoveryFailureType.InitiationFailed => true,
        SecretKeyRecoveryFailureType.ResetFailed => true,
        _ => false
    };

    public override bool IsUserFacing => FailureType switch
    {
        SecretKeyRecoveryFailureType.TokenNotFound => true,
        SecretKeyRecoveryFailureType.TokenExpired => true,
        SecretKeyRecoveryFailureType.TokenInvalid => true,
        SecretKeyRecoveryFailureType.TokenAlreadyUsed => true,
        SecretKeyRecoveryFailureType.ValidationFailed => true,
        _ => false
    };

    public override bool Retryable => FailureType switch
    {
        SecretKeyRecoveryFailureType.PersistorAccess or
        SecretKeyRecoveryFailureType.InitiationFailed or
        SecretKeyRecoveryFailureType.ResetFailed => true,
        _ => false
    };

    public override ErrorSurface Surface => FailureType switch
    {
        SecretKeyRecoveryFailureType.PersistorAccess or
        SecretKeyRecoveryFailureType.InitiationFailed or
        SecretKeyRecoveryFailureType.ResetFailed or
        SecretKeyRecoveryFailureType.InternalError => ErrorSurface.System,
        _ => ErrorSurface.User
    };

    public override string PublicErrorCode => FailureType switch
    {
        SecretKeyRecoveryFailureType.TokenNotFound => "recovery.token_not_found",
        SecretKeyRecoveryFailureType.TokenExpired => "recovery.token_expired",
        SecretKeyRecoveryFailureType.TokenInvalid => "recovery.token_invalid",
        SecretKeyRecoveryFailureType.TokenAlreadyUsed => "recovery.token_already_used",
        SecretKeyRecoveryFailureType.ValidationFailed => "recovery.validation_failed",
        SecretKeyRecoveryFailureType.InitiationFailed => "recovery.initiation_failed",
        SecretKeyRecoveryFailureType.ResetFailed => "recovery.reset_failed",
        SecretKeyRecoveryFailureType.PersistorAccess => "recovery.persistence",
        _ => "recovery.internal"
    };

    public override string? UserMessageKey => GetDefaultI18NKey(FailureType);

    public static SecretKeyRecoveryFailure TokenExpired(string? details = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.TokenExpired,
            details ?? PasswordRecoveryMessageKeys.TokenExpired);
    }

    public static SecretKeyRecoveryFailure TokenInvalid(string? details = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.TokenInvalid,
            details ?? PasswordRecoveryMessageKeys.TokenInvalid);
    }

    public static SecretKeyRecoveryFailure ResetFailed(string? details = null, Exception? ex = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.ResetFailed,
            details ?? PasswordRecoveryMessageKeys.ResetFailed, ex);
    }

    public static SecretKeyRecoveryFailure VerificationFailed(string? details = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.TokenInvalid,
            details ?? PasswordRecoveryMessageKeys.VerificationFailed);
    }

    public static SecretKeyRecoveryFailure ValidationFailed(string? details = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.ValidationFailed,
            details ?? PasswordRecoveryMessageKeys.ValidationFailed);
    }

    public static SecretKeyRecoveryFailure PersistorAccess(string? details = null, Exception? ex = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.PersistorAccess,
            details ?? PasswordRecoveryMessageKeys.DataAccess, ex);
    }

    public static SecretKeyRecoveryFailure DatabaseError(Exception? ex = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.PersistorAccess,
            PasswordRecoveryMessageKeys.DatabaseError, ex);
    }

    public static SecretKeyRecoveryFailure Timeout(Exception? ex = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.PersistorAccess,
            PasswordRecoveryMessageKeys.Timeout, ex);
    }

    public static SecretKeyRecoveryFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new SecretKeyRecoveryFailure(SecretKeyRecoveryFailureType.InternalError,
            details ?? PasswordRecoveryMessageKeys.Generic, ex);
    }

    public static SecretKeyRecoveryFailure FromAccount(AccountFailure accountFailure)
    {
        return accountFailure.FailureType switch
        {
            AccountFailureType.NotFound => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.AlreadyExists => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.ValidationFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.CreationFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.CredentialUpdateFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                accountFailure.Message,
                accountFailure.InnerException),

            AccountFailureType.PersistorAccess => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.PersistorAccess,
                accountFailure.Message,
                accountFailure.InnerException),

            _ => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.InternalError,
                accountFailure.Message,
                accountFailure.InnerException)
        };
    }

    public static SecretKeyRecoveryFailure FromMasterKey(MasterKeyFailure masterKeyFailure)
    {
        return masterKeyFailure.FailureType switch
        {
            MasterKeyFailureType.InvalidThreshold => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidShareCount => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidKeyLength => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidKeyData => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidShareData => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InvalidIdentifier => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.KeySplittingFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.KeyReconstructionFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.ShareValidationFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.InsufficientShares => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.TokenNotFound,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyStorageFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyMissing => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.TokenNotFound,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyRetrievalFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.HmacKeyRemovalFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.KeyDerivationFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.AllocationFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.MemoryReadFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.MemoryWriteFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ResetFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.ValidationFailed => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.ValidationFailed,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            MasterKeyFailureType.PersistorAccess => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.PersistorAccess,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException),

            _ => new SecretKeyRecoveryFailure(
                SecretKeyRecoveryFailureType.InternalError,
                masterKeyFailure.Message,
                masterKeyFailure.InnerException)
        };
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(UserMessageKey) ? GetDefaultI18NKey(FailureType) : UserMessageKey!;

        return FailureType switch
        {
            SecretKeyRecoveryFailureType.TokenNotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            SecretKeyRecoveryFailureType.TokenExpired => new GrpcErrorDescriptor(
                ErrorCode.OtpExpired,
                StatusCode.Unauthenticated,
                i18NKey),
            SecretKeyRecoveryFailureType.TokenInvalid => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            SecretKeyRecoveryFailureType.TokenAlreadyUsed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            SecretKeyRecoveryFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            SecretKeyRecoveryFailureType.InitiationFailed => new GrpcErrorDescriptor(
                ErrorCode.ServiceUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            SecretKeyRecoveryFailureType.ResetFailed => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            SecretKeyRecoveryFailureType.PersistorAccess => new GrpcErrorDescriptor(
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

    private static string GetDefaultI18NKey(SecretKeyRecoveryFailureType failureType) =>
        failureType switch
        {
            SecretKeyRecoveryFailureType.TokenNotFound => ErrorI18NKeys.NotFound,
            SecretKeyRecoveryFailureType.TokenExpired => ErrorI18NKeys.OtpExpired,
            SecretKeyRecoveryFailureType.TokenInvalid => ErrorI18NKeys.Unauthenticated,
            SecretKeyRecoveryFailureType.TokenAlreadyUsed => ErrorI18NKeys.Validation,
            SecretKeyRecoveryFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            SecretKeyRecoveryFailureType.InitiationFailed => ErrorI18NKeys.ServiceUnavailable,
            SecretKeyRecoveryFailureType.ResetFailed => ErrorI18NKeys.DatabaseUnavailable,
            SecretKeyRecoveryFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
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
            IsUserFacing,
            Retryable,
            Surface = Surface.ToString(),
            PublicErrorCode
        };
    }
}
