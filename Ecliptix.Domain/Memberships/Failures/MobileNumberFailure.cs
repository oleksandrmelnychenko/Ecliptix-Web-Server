using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record MobileNumberFailure(
    MobileNumberFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        MobileNumberFailureType.PersistorAccess => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        MobileNumberFailureType.Invalid => true,
        MobileNumberFailureType.TooShort => true,
        MobileNumberFailureType.TooLong => true,
        MobileNumberFailureType.InvalidCountryCode => true,
        MobileNumberFailureType.ValidationFailed => true,
        MobileNumberFailureType.AlreadyExists => true,
        _ => false
    };

    public static MobileNumberFailure Invalid(string? details = null, Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.Invalid,
            details ?? MobileNumberMessageKeys.MobileNumberInvalid, ex);
    }

    public static MobileNumberFailure Empty()
    {
        return new MobileNumberFailure(MobileNumberFailureType.ValidationFailed,
            MobileNumberMessageKeys.MobileNumberEmpty);
    }

    public static MobileNumberFailure CannotBeEmpty()
    {
        return new MobileNumberFailure(MobileNumberFailureType.ValidationFailed,
            MobileNumberMessageKeys.MobileNumberCannotBeEmpty);
    }

    public static MobileNumberFailure TooShort()
    {
        return new MobileNumberFailure(MobileNumberFailureType.TooShort,
            MobileNumberMessageKeys.MobileNumberTooShort);
    }

    public static MobileNumberFailure TooLong()
    {
        return new MobileNumberFailure(MobileNumberFailureType.TooLong,
            MobileNumberMessageKeys.MobileNumberTooLong);
    }

    public static MobileNumberFailure InvalidCountryCode()
    {
        return new MobileNumberFailure(MobileNumberFailureType.InvalidCountryCode,
            MobileNumberMessageKeys.InvalidCountryCode);
    }

    public static MobileNumberFailure InvalidNumber()
    {
        return new MobileNumberFailure(MobileNumberFailureType.Invalid,
            MobileNumberMessageKeys.InvalidNumber);
    }

    public static MobileNumberFailure ParsingFailed(string? details = null, Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.ParsingFailed,
            details ?? MobileNumberMessageKeys.ParsingFailed, ex);
    }

    public static MobileNumberFailure ParsingGenericError(Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.ParsingFailed,
            MobileNumberMessageKeys.ParsingGenericError, ex);
    }

    public static MobileNumberFailure ParsingPossibleButLocalOnly()
    {
        return new MobileNumberFailure(MobileNumberFailureType.ParsingFailed,
            MobileNumberMessageKeys.ParsingPossibleButLocalOnly);
    }

    public static MobileNumberFailure InvalidDefaultRegion()
    {
        return new MobileNumberFailure(MobileNumberFailureType.ValidationFailed,
            MobileNumberMessageKeys.InvalidDefaultRegion);
    }

    public static MobileNumberFailure NotFound(string? details = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.NotFound,
            details ?? MobileNumberMessageKeys.MobileNotFound);
    }

    public static MobileNumberFailure EntityNotFound()
    {
        return new MobileNumberFailure(MobileNumberFailureType.NotFound,
            MobileNumberMessageKeys.MobileNumberNotFoundEntity);
    }

    public static MobileNumberFailure EnsureFailed(Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.PersistorAccess,
            MobileNumberMessageKeys.EnsureMobileFailed, ex);
    }

    public static MobileNumberFailure GetFailed(Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.PersistorAccess,
            MobileNumberMessageKeys.GetMobileFailed, ex);
    }

    public static MobileNumberFailure CheckAvailabilityFailed(Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.PersistorAccess,
            MobileNumberMessageKeys.CheckMobileAvailabilityFailed, ex);
    }

    public static MobileNumberFailure ValidationFailed(string? details = null, Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.ValidationFailed,
            details ?? MobileNumberMessageKeys.Generic, ex);
    }

    public static MobileNumberFailure ValidationUnexpectedError(Exception ex)
    {
        return new MobileNumberFailure(MobileNumberFailureType.ValidationFailed,
            MobileNumberMessageKeys.ValidationUnexpectedError, ex);
    }

    public static MobileNumberFailure AlreadyExists(string? details = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.AlreadyExists,
            details ?? MobileNumberMessageKeys.Generic);
    }

    public static MobileNumberFailure PersistorAccess(string? details = null, Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.PersistorAccess,
            details ?? MobileNumberMessageKeys.DataAccess, ex);
    }

    public static MobileNumberFailure DatabaseError(Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.PersistorAccess,
            MobileNumberMessageKeys.DatabaseError, ex);
    }

    public static MobileNumberFailure Timeout(Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.PersistorAccess,
            MobileNumberMessageKeys.Timeout, ex);
    }

    public static MobileNumberFailure InternalError(string? details = null, Exception? ex = null)
    {
        return new MobileNumberFailure(MobileNumberFailureType.InternalError,
            details ?? MobileNumberMessageKeys.Generic, ex);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            MobileNumberFailureType.Invalid => new GrpcErrorDescriptor(
                ErrorCode.InvalidMobileNumber,
                StatusCode.InvalidArgument,
                i18NKey),
            MobileNumberFailureType.TooShort or
            MobileNumberFailureType.TooLong or
            MobileNumberFailureType.InvalidCountryCode or
            MobileNumberFailureType.ParsingFailed => new GrpcErrorDescriptor(
                ErrorCode.InvalidMobileNumber,
                StatusCode.InvalidArgument,
                i18NKey),
            MobileNumberFailureType.ValidationFailed => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            MobileNumberFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            MobileNumberFailureType.AlreadyExists => new GrpcErrorDescriptor(
                ErrorCode.AlreadyExists,
                StatusCode.AlreadyExists,
                i18NKey),
            MobileNumberFailureType.PersistorAccess => new GrpcErrorDescriptor(
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

    private static string GetDefaultI18NKey(MobileNumberFailureType failureType) =>
        failureType switch
        {
            MobileNumberFailureType.Invalid => ErrorI18NKeys.InvalidMobile,
            MobileNumberFailureType.TooShort => MobileNumberMessageKeys.MobileNumberTooShort,
            MobileNumberFailureType.TooLong => MobileNumberMessageKeys.MobileNumberTooLong,
            MobileNumberFailureType.InvalidCountryCode => MobileNumberMessageKeys.InvalidCountryCode,
            MobileNumberFailureType.ParsingFailed => MobileNumberMessageKeys.ParsingFailed,
            MobileNumberFailureType.ValidationFailed => ErrorI18NKeys.Validation,
            MobileNumberFailureType.NotFound => ErrorI18NKeys.NotFound,
            MobileNumberFailureType.AlreadyExists => ErrorI18NKeys.AlreadyExists,
            MobileNumberFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
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
