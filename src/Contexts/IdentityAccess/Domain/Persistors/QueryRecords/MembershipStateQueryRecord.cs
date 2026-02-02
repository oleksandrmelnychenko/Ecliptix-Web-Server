using Ecliptix.Protobuf.Membership;

namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

public record MembershipStateQueryRecord
{
    public MobileNumberAvailabilityStatus AvailabilityStatus { get; init; }
    public Membership.Types.CreationStatus CreationStatus { get; init; }
    public Membership.Types.ActivityStatus ActivityStatus { get; init; }
    public bool CanContinue { get; init; }
    public string LocalizationKey { get; init; } = string.Empty;
}
