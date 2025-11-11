using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record AccountInfo(
    Guid AccountId,
    Guid MembershipId,
    AccountType Type,
    string Name,
    bool IsDefault,
    AccountStatus Status);
