namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

public record AccountCreationResult(
    List<AccountInfo> Accounts,
    AccountInfo ActiveAccount);
