namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryResults;

public class ExistingMembershipResult
{
    public bool MembershipExists { get; set; }
    public Protobuf.Membership.Membership? Membership { get; set; }
}
