using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record FlowStatusQueryRecord(
    bool IsFound,
    VerificationFlowStatus Status,
    DateTimeOffset ExpiresAt);
