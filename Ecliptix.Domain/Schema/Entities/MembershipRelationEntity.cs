namespace Ecliptix.Domain.Schema.Entities;

public enum MembershipRelationStatus
{
    Blocked = 1,
    Removed = 2
}

public class MembershipRelationEntity : EntityBase
{
    public long InitiatorAccountId { get; set; }
    public long RecipientAccountId { get; set; }
    public MembershipRelationStatus? Status { get; set; }
    public string? Message { get; set; }
    public string? MetaJson { get; set; }
    public long GetOtherAccountId(long accountId) => 
        accountId == InitiatorAccountId ? RecipientAccountId : InitiatorAccountId;

    public virtual AccountEntity InitiatorAccount { get; set; } = null!;
    public virtual AccountEntity RecipientAccount { get; set; } = null!;
}
