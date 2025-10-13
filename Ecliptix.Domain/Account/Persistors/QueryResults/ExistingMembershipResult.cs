namespace Ecliptix.Domain.Account.Persistors.QueryResults;

public class ExistingAccountResult
{
    public bool AccountExists { get; set; }
    public Protobuf.Account.Account? Account { get; set; }
}