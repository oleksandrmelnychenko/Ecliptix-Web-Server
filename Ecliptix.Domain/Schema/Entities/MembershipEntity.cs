namespace Ecliptix.Domain.Schema.Entities;

public class MembershipEntity : EntityBase
{
    public virtual ICollection<AccountEntity> Accounts { get; set; } = new List<AccountEntity>();
    public virtual ICollection<MasterKeyShareEntity> MasterKeyShares { get; set; } = new List<MasterKeyShareEntity>();

}