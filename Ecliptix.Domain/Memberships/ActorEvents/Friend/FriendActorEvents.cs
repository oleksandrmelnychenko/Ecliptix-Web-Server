using Ecliptix.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.Domain.Memberships.ActorEvents.Friend;

public record SendFriendRequestEvent(
    uint ConnectId,
    Guid FromMembershipId,
    Guid ToMembershipId,
    string? Message,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record AcceptFriendRequestEvent(
    uint ConnectId,
    Guid ByMembershipId,
    Guid FromMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RejectFriendRequestEvent(
    uint ConnectId,
    Guid ByMembershipId,
    Guid FromMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record CancelFriendRequestEvent(
    uint ConnectId,
    Guid FromMembershipId,
    Guid ToMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record RemoveFriendEvent(
    uint ConnectId,
    Guid MembershipId,
    Guid FriendMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record ListFriendsEvent(
    uint ConnectId,
    Guid MembershipId,
    int Limit,
    string? Cursor,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetFriendshipStatusEvent(
    uint ConnectId,
    Guid MembershipId,
    Guid OtherMembershipId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

