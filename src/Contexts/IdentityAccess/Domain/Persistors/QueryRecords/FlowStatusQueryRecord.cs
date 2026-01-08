using Ecliptix.IdentityAccess.Domain.Memberships;

namespace Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;

public record FlowStatusQueryRecord(
    bool IsFound,
    VerificationFlowStatus Status,
    DateTimeOffset ExpiresAt);
