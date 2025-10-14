namespace Ecliptix.Domain.Schema.Entities;

public class MembershipEntity : EntityBase
{
    public virtual ICollection<AccountEntity> Accounts { get; set; } = new List<AccountEntity>();
}