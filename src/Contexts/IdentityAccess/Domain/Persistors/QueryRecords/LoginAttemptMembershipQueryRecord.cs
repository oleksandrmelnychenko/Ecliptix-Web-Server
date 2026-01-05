using Ecliptix.IdentityAccess.Domain.Schema.Entities;

namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

public readonly record struct LoginAttemptMembershipQueryRecord
{
    public required LoginAttemptEntity LoginAttempt { get; init; }
    public required MembershipEntity Membership { get; init; }
}
