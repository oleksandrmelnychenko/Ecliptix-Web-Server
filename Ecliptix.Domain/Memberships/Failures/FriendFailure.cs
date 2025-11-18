using Ecliptix.Utilities;

namespace Ecliptix.Domain.Memberships.Failures;

public sealed record FriendFailure(
    FriendFailureType FailureType,
    string Message,
    Exception? InnerException = null)
    : FailureBase(Message, InnerException)
{
    
    public bool IsUserFacing { get; init; } = false;

    public static FriendFailure ValidationFailed(string? details = null)
    {
        return new FriendFailure(FriendFailureType.ValidationFailed, 
            details ?? FriendMessageKeys.ValidationFailed);
    }
    
    public static FriendFailure NotFound(string? details = null)
    {
        return new FriendFailure(FriendFailureType.NotFound,
            details ?? FriendMessageKeys.FriendNotFound);
    }

    public static FriendFailure AlreadyRequested(string details = "Friend request already sent")
    {
        return new FriendFailure(FriendFailureType.AlreadyRequested, details);
    }
    
    public static FriendFailure AlreadyFriends(string details = "Already friends")
    {
        return new FriendFailure(FriendFailureType.AlreadyFriends, details);
    }
    
    public static FriendFailure Blocked(string details = "Membership is blocked")
    {
        return new FriendFailure(FriendFailureType.Blocked, details);
    }
    
    public static FriendFailure DatabaseError(string details, Exception? exception = null)
    {
        return new FriendFailure(FriendFailureType.PersistorAccess, details, exception);
    }
    
     public static FriendFailure UnexpectedError(string details, Exception? exception = null)
     {
         return new FriendFailure(FriendFailureType.UnexpectedError, details, exception);
     }
  
    public override object ToStructuredLog()
    {
        throw new NotImplementedException();
    }

    public override GrpcErrorDescriptor ToGrpcDescriptor()
    {
        throw new NotImplementedException();
    }
}

