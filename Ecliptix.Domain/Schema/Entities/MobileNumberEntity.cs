
namespace Ecliptix.Domain.Schema.Entities;

public class MobileNumberEntity : EntityBase
{
    public string Number { get; set; } = string.Empty;
    public string? Region { get; set; }

    public virtual ICollection<AccountEntity> Accounts { get; set; } = new List<AccountEntity>();
    public virtual ICollection<LoginAttemptEntity> LoginAttempts { get; set; } = new List<LoginAttemptEntity>();
    public virtual ICollection<VerificationFlowEntity> VerificationFlows { get; set; } = new List<VerificationFlowEntity>();
}