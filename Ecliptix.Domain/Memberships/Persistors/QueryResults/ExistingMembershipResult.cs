namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

public class ExistingMembershipResult
{
    public bool MembershipExists { get; set; }
    public Protobuf.Membership.Membership? Membership { get; set; }
}