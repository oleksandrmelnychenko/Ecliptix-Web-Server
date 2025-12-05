using Ecliptix.Utilities;
using Grpc.Core;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record ContactFailure(
    ContactFailureType FailureType,
    string Message,
    FailureBase? SourceFailure = null,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        ContactFailureType.PersistorAccess => true,
        ContactFailureType.ConcurrencyConflict => true,
        ContactFailureType.DatabaseError => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        ContactFailureType.NotFound => true,
        ContactFailureType.AlreadyContact => true,
        ContactFailureType.Blocked => true,
        ContactFailureType.InvalidRequest => true,
        ContactFailureType.Validation => true,
        ContactFailureType.Unauthorized => true,
        _ => false
    };

    public static ContactFailure NotFound(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.NotFound,
            details ?? ContactMessageKeys.ContactNotFound);
    }

    public static ContactFailure ContactRelationNotFound(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.NotFound,
            details ?? ContactMessageKeys.ContactRelationNotFound);
    }

    public static ContactFailure ContactRequestNotFound(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.NotFound,
            details ?? ContactMessageKeys.ContactNotFound);
    }

    public static ContactFailure AlreadyContact(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.AlreadyContact,
            details ?? ContactMessageKeys.AlreadyContact);
    }

    public static ContactFailure Blocked(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.Blocked,
            details ?? ContactMessageKeys.UserBlocked);
    }

    public static ContactFailure BlockedByUser(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.Blocked,
            details ?? ContactMessageKeys.BlockedByUser);
    }

    public static ContactFailure CannotContactYourself()
    {
        return new ContactFailure(
            ContactFailureType.InvalidRequest,
            ContactMessageKeys.CannotAddYourself);
    }

    public static ContactFailure CannotAcceptOwnRequest()
    {
        return new ContactFailure(
            ContactFailureType.InvalidRequest,
            ContactMessageKeys.InvalidMembershipId);
    }

    public static ContactFailure CannotCancelOtherRequest()
    {
        return new ContactFailure(
            ContactFailureType.InvalidRequest,
            ContactMessageKeys.InvalidMembershipId);
    }

    public static ContactFailure RequestNotPending()
    {
        return new ContactFailure(
            ContactFailureType.InvalidRequest,
            ContactMessageKeys.ContactNotFound);
    }

    public static ContactFailure NotContacts()
    {
        return new ContactFailure(
            ContactFailureType.InvalidRequest,
            ContactMessageKeys.NotInContacts);
    }

    public static ContactFailure ValidationFailed(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.Validation,
            details ?? ContactMessageKeys.ValidationFailed);
    }

    public static ContactFailure InvalidMembershipId(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.Validation,
            details ?? ContactMessageKeys.InvalidMembershipId);
    }

    public static ContactFailure PersistorAccess(string? details = null, Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            details ?? ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure SendRequestFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure AcceptRequestFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure RejectRequestFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure CancelRequestFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure RemoveContactFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.RemoveContactFailed,
            InnerException: innerException);
    }

    public static ContactFailure ListContactsFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.ListContactsFailed,
            InnerException: innerException);
    }

    public static ContactFailure GetContactshipStatusFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.GetContactStatusFailed,
            InnerException: innerException);
    }

    public static ContactFailure BlockUserFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.BlockContactFailed,
            InnerException: innerException);
    }

    public static ContactFailure UnblockUserFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.UnblockContactFailed,
            InnerException: innerException);
    }

    public static ContactFailure ListPendingRequestsFailed(Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.PersistorAccess,
            ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure ConcurrencyConflict(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.ConcurrencyConflict,
            details ?? ContactMessageKeys.ConcurrencyConflict);
    }

    public static ContactFailure DatabaseError(string? details = null, Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.DatabaseError,
            details ?? ContactMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static ContactFailure Unauthorized(string? details = null)
    {
        return new ContactFailure(
            ContactFailureType.Unauthorized,
            details ?? "Unauthorized");
    }

    public static ContactFailure Generic(string? details = null, Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.Generic,
            details ?? ContactMessageKeys.Generic,
            null,
            innerException);
    }

    public static ContactFailure UnexpectedError(string? details = null, Exception? innerException = null)
    {
        return new ContactFailure(
            ContactFailureType.Generic,
            details ?? ContactMessageKeys.UnexpectedError,
            null,
            innerException);
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        string i18NKey = string.IsNullOrWhiteSpace(Message) ? GetDefaultI18NKey(FailureType) : Message;

        return FailureType switch
        {
            ContactFailureType.NotFound => new GrpcErrorDescriptor(
                ErrorCode.NotFound,
                StatusCode.NotFound,
                i18NKey),
            
            ContactFailureType.AlreadyContact => new GrpcErrorDescriptor(
                ErrorCode.AlreadyExists,
                StatusCode.AlreadyExists,
                i18NKey),
            
            ContactFailureType.Blocked => new GrpcErrorDescriptor(
                ErrorCode.PermissionDenied,
                StatusCode.PermissionDenied,
                i18NKey),
            
            ContactFailureType.InvalidRequest => new GrpcErrorDescriptor(
                ErrorCode.PreconditionFailed,
                StatusCode.FailedPrecondition,
                i18NKey),
            
            ContactFailureType.Validation => new GrpcErrorDescriptor(
                ErrorCode.ValidationFailed,
                StatusCode.InvalidArgument,
                i18NKey),
            
            ContactFailureType.Unauthorized => new GrpcErrorDescriptor(
                ErrorCode.Unauthenticated,
                StatusCode.Unauthenticated,
                i18NKey),
            
            ContactFailureType.ConcurrencyConflict => new GrpcErrorDescriptor(
                ErrorCode.Conflict,
                StatusCode.Aborted,
                i18NKey),
            
            ContactFailureType.PersistorAccess => new GrpcErrorDescriptor(
                ErrorCode.DatabaseUnavailable,
                StatusCode.Unavailable,
                i18NKey,
                Retryable: true),
            
            ContactFailureType.DatabaseError => new GrpcErrorDescriptor(
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

    private static string GetDefaultI18NKey(ContactFailureType failureType) =>
        failureType switch
        {
            ContactFailureType.NotFound => ErrorI18NKeys.NotFound,
            ContactFailureType.AlreadyContact => ErrorI18NKeys.AlreadyExists,
            ContactFailureType.Blocked => ErrorI18NKeys.PermissionDenied,
            ContactFailureType.InvalidRequest => ErrorI18NKeys.PreconditionFailed,
            ContactFailureType.Validation => ErrorI18NKeys.Validation,
            ContactFailureType.Unauthorized => ErrorI18NKeys.Unauthenticated,
            ContactFailureType.ConcurrencyConflict => ErrorI18NKeys.Conflict,
            ContactFailureType.PersistorAccess => ErrorI18NKeys.DatabaseUnavailable,
            ContactFailureType.DatabaseError => ErrorI18NKeys.DatabaseUnavailable,
            _ => ErrorI18NKeys.Internal
        };

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            IsRecoverable,
            IsUserFacing,
            SourceFailure = SourceFailure?.Message,
            InnerException = InnerException?.Message,
            Timestamp
        };
    }
}

