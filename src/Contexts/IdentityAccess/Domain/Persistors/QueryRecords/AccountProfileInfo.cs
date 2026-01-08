namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

public record AccountProfileInfo(
    Guid ProfileId,
    Guid AccountId,
    string ProfileName,
    string DisplayName
);
