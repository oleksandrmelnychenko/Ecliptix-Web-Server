namespace Ecliptix.Domain.Schema.Entities;

public class MobileNumberEntity : EntityBase
{
    public string Number { get; set; } = string.Empty;
    public string? Region { get; set; }

    public List<VerificationFlowEntity> VerificationFlows
    {
        get => field ??= [];
        set;
    }

    public List<MembershipEntity> Memberships
    {
        get => field ??= [];
        set;
    }
}
