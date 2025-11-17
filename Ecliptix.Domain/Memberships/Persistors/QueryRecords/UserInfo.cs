namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record UserInfo(
    Guid UserId,
    Guid AccountId,
    string UserName,
    string DisplayName
);
