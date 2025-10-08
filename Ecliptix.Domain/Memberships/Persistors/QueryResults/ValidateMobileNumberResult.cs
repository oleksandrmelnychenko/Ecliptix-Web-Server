using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

public class ValidateMobileNumberResult
{
    public Guid MobileNumberId { get; set; }
    public Membership? Membership { get; set; }
}