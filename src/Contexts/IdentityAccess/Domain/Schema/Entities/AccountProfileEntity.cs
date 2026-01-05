namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class AccountProfileEntity : EntityBase
{
    public Guid AccountId { get; set; }

    public AccountEntity Account { get; set; } = null!;

    public string ProfileName { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;
}
