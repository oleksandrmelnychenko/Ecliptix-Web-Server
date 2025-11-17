namespace Ecliptix.Domain.Schema.Entities;

public class UserEntity : EntityBase
{
    public Guid AccountId { get; set; }

    public virtual AccountEntity Account { get; set; } = null!;

    public string UserName { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;


}
