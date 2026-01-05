using Ecliptix.Protobuf.Account;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

public record AccountInfo(
    Guid AccountId,
    Guid MembershipId,
    AccountType Type,
    bool IsDefault,
    AccountStatus Status);
