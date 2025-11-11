namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record AccountCreationResult(
    List<AccountInfo> Accounts,
    AccountInfo ActiveAccount);
