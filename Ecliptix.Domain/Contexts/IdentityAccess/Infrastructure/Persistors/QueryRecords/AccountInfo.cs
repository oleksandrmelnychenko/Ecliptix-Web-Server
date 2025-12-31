using Ecliptix.Protobuf.Account;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record AccountInfo(
    Guid AccountId,
    Guid MembershipId,
    AccountType Type,
    bool IsDefault,
    AccountStatus Status);
