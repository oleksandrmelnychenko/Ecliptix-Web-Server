using Ecliptix.Protobuf.Account;

namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

public record AccountInfo(
    Guid AccountId,
    Guid MembershipId,
    AccountType Type,
    bool IsDefault,
    AccountStatus Status);
