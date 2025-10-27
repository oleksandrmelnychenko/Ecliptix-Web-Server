using Ecliptix.Domain.Schema.Entities;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public readonly record struct LoginAttemptMembershipQueryRecord
{
    public required LoginAttemptEntity LoginAttempt { get; init; }
    public required MembershipEntity Membership { get; init; }
}
