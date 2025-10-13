using AccountProto = Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Account.Persistors.QueryResults;

public class ValidateMobileNumberResult
{
    public Guid MobileNumberId { get; set; }
    public AccountProto.Account? Account { get; set; }
}