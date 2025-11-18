using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record FriendFailure(
    FriendFailureType FailureType,
    string Message,
    FailureBase? SourceFailure = null,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    public bool IsRecoverable => FailureType switch
    {
        FriendFailureType.PersistorAccess => true,
        FriendFailureType.ConcurrencyConflict => true,
        FriendFailureType.DatabaseError => true,
        _ => false
    };

    public bool IsUserFacing => FailureType switch
    {
        FriendFailureType.NotFound => true,
        FriendFailureType.AlreadyRequested => true,
        FriendFailureType.AlreadyFriends => true,
        FriendFailureType.Blocked => true,
        FriendFailureType.InvalidRequest => true,
        FriendFailureType.Validation => true,
        FriendFailureType.Unauthorized => true,
        _ => false
    };

    public static FriendFailure NotFound(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.NotFound,
            details ?? FriendMessageKeys.FriendNotFound);
    }

    public static FriendFailure FriendRelationNotFound(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.NotFound,
            details ?? FriendMessageKeys.FriendRelationNotFound);
    }

    public static FriendFailure FriendRequestNotFound(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.NotFound,
            details ?? FriendMessageKeys.FriendRequestNotFound);
    }

    public static FriendFailure AlreadyRequested(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.AlreadyRequested,
            details ?? FriendMessageKeys.AlreadyRequested);
    }

    public static FriendFailure AlreadyFriends(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.AlreadyFriends,
            details ?? FriendMessageKeys.AlreadyFriends);
    }

    public static FriendFailure Blocked(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.Blocked,
            details ?? FriendMessageKeys.UserBlocked);
    }

    public static FriendFailure BlockedByUser(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.Blocked,
            details ?? FriendMessageKeys.BlockedByUser);
    }

    public static FriendFailure CannotFriendYourself()
    {
        return new FriendFailure(
            FriendFailureType.InvalidRequest,
            FriendMessageKeys.CannotFriendYourself);
    }

    public static FriendFailure CannotAcceptOwnRequest()
    {
        return new FriendFailure(
            FriendFailureType.InvalidRequest,
            FriendMessageKeys.CannotAcceptOwnRequest);
    }

    public static FriendFailure CannotCancelOtherRequest()
    {
        return new FriendFailure(
            FriendFailureType.InvalidRequest,
            FriendMessageKeys.CannotCancelOtherRequest);
    }

    public static FriendFailure RequestNotPending()
    {
        return new FriendFailure(
            FriendFailureType.InvalidRequest,
            FriendMessageKeys.RequestNotPending);
    }

    public static FriendFailure NotFriends()
    {
        return new FriendFailure(
            FriendFailureType.InvalidRequest,
            FriendMessageKeys.NotFriends);
    }

    public static FriendFailure ValidationFailed(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.Validation,
            details ?? FriendMessageKeys.ValidationFailed);
    }

    public static FriendFailure InvalidMembershipId(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.Validation,
            details ?? FriendMessageKeys.InvalidMembershipId);
    }

    public static FriendFailure PersistorAccess(string? details = null, Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            details ?? FriendMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static FriendFailure SendRequestFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.SendRequestFailed,
            InnerException: innerException);
    }

    public static FriendFailure AcceptRequestFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.AcceptRequestFailed,
            InnerException: innerException);
    }

    public static FriendFailure RejectRequestFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.RejectRequestFailed,
            InnerException: innerException);
    }

    public static FriendFailure CancelRequestFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.CancelRequestFailed,
            InnerException: innerException);
    }

    public static FriendFailure RemoveFriendFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.RemoveFriendFailed,
            InnerException: innerException);
    }

    public static FriendFailure ListFriendsFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.ListFriendsFailed,
            InnerException: innerException);
    }

    public static FriendFailure GetFriendshipStatusFailed(Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.PersistorAccess,
            FriendMessageKeys.GetFriendshipStatusFailed,
            InnerException: innerException);
    }

    public static FriendFailure ConcurrencyConflict(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.ConcurrencyConflict,
            details ?? FriendMessageKeys.ConcurrencyConflict);
    }

    public static FriendFailure DatabaseError(string? details = null, Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.DatabaseError,
            details ?? FriendMessageKeys.DataAccess,
            InnerException: innerException);
    }

    public static FriendFailure Unauthorized(string? details = null)
    {
        return new FriendFailure(
            FriendFailureType.Unauthorized,
            details ?? "Unauthorized");
    }

    public static FriendFailure Generic(string? details = null, Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.Generic,
            details ?? FriendMessageKeys.Generic,
            null,
            innerException);
    }

    public static FriendFailure UnexpectedError(string? details = null, Exception? innerException = null)
    {
        return new FriendFailure(
            FriendFailureType.Generic,
            details ?? FriendMessageKeys.UnexpectedError,
            null,
            innerException);
    }

    public override object ToStructuredLog()
    {
        return new
        {
            FailureType = FailureType.ToString(),
            Message,
            IsRecoverable,
            IsUserFacing,
            SourceFailure = SourceFailure?.Message,
            InnerException = InnerException?.Message
        };
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        throw new NotImplementedException();
    }
}

