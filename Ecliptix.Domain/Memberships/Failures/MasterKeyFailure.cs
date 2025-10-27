using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record MasterKeyFailure(
    MasterKeyFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        MasterKeyFailureType.AllocationFailed => true,
        MasterKeyFailureType.PersistorAccess => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        MasterKeyFailureType.InvalidThreshold => true,
        MasterKeyFailureType.InvalidShareCount => true,
        MasterKeyFailureType.InvalidKeyLength => true,
        MasterKeyFailureType.InvalidKeyData => true,
        MasterKeyFailureType.InvalidShareData => true,
        MasterKeyFailureType.InvalidIdentifier => true,
        MasterKeyFailureType.ShareValidationFailed => true,
        MasterKeyFailureType.InsufficientShares => true,
        _ => false
    };

    public static MasterKeyFailure InvalidIdentifier(string details)
    {
        return new MasterKeyFailure(MasterKeyFailureType.InvalidIdentifier,
            $"{MasterKeyMessageKeys.InvalidIdentifier}: {details}");
    }

    public static MasterKeyFailure KeySplittingFailed(string details, Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.KeySplittingFailed,
            $"{MasterKeyMessageKeys.KeySplittingFailed}: {details}", ex);
    }

    public static MasterKeyFailure NoSharesProvided()
    {
        return new MasterKeyFailure(MasterKeyFailureType.KeySplittingFailed,
            MasterKeyMessageKeys.NoSharesProvided);
    }

    public static MasterKeyFailure DuplicateShareIndexes()
    {
        return new MasterKeyFailure(MasterKeyFailureType.KeySplittingFailed,
            MasterKeyMessageKeys.DuplicateShareIndexes);
    }

    public static MasterKeyFailure SharesAlreadyExist()
    {
        return new MasterKeyFailure(MasterKeyFailureType.KeySplittingFailed,
            MasterKeyMessageKeys.SharesAlreadyExist);
    }

    public static MasterKeyFailure SharesNotFound()
    {
        return new MasterKeyFailure(MasterKeyFailureType.KeyReconstructionFailed,
            MasterKeyMessageKeys.SharesNotFound);
    }

    public static MasterKeyFailure MembershipNotFoundOrInactive()
    {
        return new MasterKeyFailure(MasterKeyFailureType.InvalidIdentifier,
            MasterKeyMessageKeys.MembershipNotFoundOrInactive);
    }

    public static MasterKeyFailure DefaultAccountNotFound()
    {
        return new MasterKeyFailure(MasterKeyFailureType.InvalidIdentifier,
            MasterKeyMessageKeys.DefaultAccountNotFound);
    }

    public static MasterKeyFailure CredentialsNotFound()
    {
        return new MasterKeyFailure(MasterKeyFailureType.InvalidIdentifier,
            MasterKeyMessageKeys.CredentialsNotFound);
    }

    public static MasterKeyFailure DatabaseError(Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.PersistorAccess,
            MasterKeyMessageKeys.DatabaseError, ex);
    }

    public static MasterKeyFailure Timeout(Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.PersistorAccess,
            MasterKeyMessageKeys.Timeout, ex);
    }

    public static MasterKeyFailure InsertFailed(string details, Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.PersistorAccess,
            $"{MasterKeyMessageKeys.InsertFailed}: {details}", ex);
    }

    public static MasterKeyFailure QueryFailed(Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.PersistorAccess,
            MasterKeyMessageKeys.QueryFailed, ex);
    }

    public static MasterKeyFailure DeleteFailed(Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.PersistorAccess,
            MasterKeyMessageKeys.DeleteFailed, ex);
    }

    public static MasterKeyFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new MasterKeyFailure(MasterKeyFailureType.InternalError,
            details ?? MasterKeyMessageKeys.Generic, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = GetDefaultI18NKey(FailureType);

        return FailureType switch
        {
            MasterKeyFailureType.InvalidThreshold or
            MasterKeyFailureType.InvalidShareCount or
            MasterKeyFailureType.InvalidKeyLength or
            MasterKeyFailureType.InvalidKeyData or
            MasterKeyFailureType.InvalidShareData or
            MasterKeyFailureType.InvalidIdentifier or
            MasterKeyFailureType.ShareValidationFailed or
            MasterKeyFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),

            MasterKeyFailureType.InsufficientShares => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                i18NKey),

            MasterKeyFailureType.HmacKeyMissing => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),

            MasterKeyFailureType.AllocationFailed => new GrpcErrorDescriptor(
                ErrorCode.ResourceExhausted,
                StatusCode.ResourceExhausted,
                i18NKey,
                Retryable: true),

            MasterKeyFailureType.PersistorAccess => new GrpcErrorDescriptor(
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

    private static string GetDefaultI18NKey(MasterKeyFailureType failureType) =>
        failureType switch
        {
            MasterKeyFailureType.InvalidThreshold => MasterKeyMessageKeys.InvalidThreshold,
            MasterKeyFailureType.InvalidShareCount => MasterKeyMessageKeys.InvalidShareCount,
            MasterKeyFailureType.InvalidKeyLength => MasterKeyMessageKeys.InvalidKeyLength,
            MasterKeyFailureType.InvalidKeyData => MasterKeyMessageKeys.InvalidKeyData,
            MasterKeyFailureType.InvalidShareData => MasterKeyMessageKeys.InvalidShareData,
            MasterKeyFailureType.InvalidIdentifier => MasterKeyMessageKeys.InvalidIdentifier,
            MasterKeyFailureType.ShareValidationFailed => MasterKeyMessageKeys.ShareValidationFailed,
            MasterKeyFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            MasterKeyFailureType.InsufficientShares => MasterKeyMessageKeys.InsufficientShares,
            MasterKeyFailureType.HmacKeyMissing => ErrorI18NKeys.NotFound,
            MasterKeyFailureType.AllocationFailed => ErrorI18NKeys.ResourceExhausted,
            MasterKeyFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
            MasterKeyFailureType.KeySplittingFailed => MasterKeyMessageKeys.KeySplittingFailed,
            MasterKeyFailureType.KeyReconstructionFailed => MasterKeyMessageKeys.KeyReconstructionFailed,
            MasterKeyFailureType.KeyDerivationFailed => MasterKeyMessageKeys.KeyDerivationFailed,
            MasterKeyFailureType.HmacKeyStorageFailed => MasterKeyMessageKeys.HmacKeyStorageFailed,
            MasterKeyFailureType.HmacKeyRetrievalFailed => MasterKeyMessageKeys.HmacKeyRetrievalFailed,
            MasterKeyFailureType.HmacKeyRemovalFailed => MasterKeyMessageKeys.HmacKeyRemovalFailed,
            MasterKeyFailureType.MemoryReadFailed => MasterKeyMessageKeys.MemoryReadFailed,
            MasterKeyFailureType.MemoryWriteFailed => MasterKeyMessageKeys.MemoryWriteFailed,
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
