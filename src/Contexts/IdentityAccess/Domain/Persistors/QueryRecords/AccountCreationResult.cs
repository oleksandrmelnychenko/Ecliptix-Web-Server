namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

public record AccountCreationResult(
    List<AccountInfo> Accounts,
    AccountInfo ActiveAccount);
