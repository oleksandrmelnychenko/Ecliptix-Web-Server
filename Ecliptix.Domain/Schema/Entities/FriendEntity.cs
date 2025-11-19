namespace Ecliptix.Domain.Schema.Entities;

public enum FriendRelationStatus
{
    Pending = 0,
    Accepted = 1,
    Rejected = 2,
    Blocked = 3,
    Removed = 4
}

public class FriendEntity : EntityBase
{
    public Guid UserAId { get; set; }
    public Guid UserBId { get; set; }

    public Guid RequestedById { get; set; }

    public FriendRelationStatus Status { get; set; } = FriendRelationStatus.Pending;

    public DateTimeOffset? AcceptedAt { get; set; }

    public string? Message { get; set; }

    public string? MetaJson { get; set; }

    public Guid OtherUserId(Guid ownerId) => ownerId == UserAId ? UserBId : UserAId;
}
