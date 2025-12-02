namespace Ecliptix.Domain.Schema.Entities;

public enum ContactStatus
{
    Blocked = 1,
    Removed = 2,
    Muted = 3
}

public class MembershipRelationEntity : EntityBase
{
    public long InitiatorAccountId { get; set; }
    public long RecipientAccountId { get; set; }
    public ContactStatus? Status { get; set; }
    public string? Message { get; set; }
    public string? MetaJson { get; set; }
    public DateTimeOffset? MutedUntil { get; set; }

    public long GetOtherAccountId(long accountId) =>
        accountId == InitiatorAccountId ? RecipientAccountId : InitiatorAccountId;

    // Navigation properties - no virtual for better performance
    public AccountEntity InitiatorAccount { get; set; } = null!;
    public AccountEntity RecipientAccount { get; set; } = null!;
}
