namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

public record AccountProfileInfo(
    Guid ProfileId,
    Guid AccountId,
    string ProfileName,
    string DisplayName
);
