namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

public record FlowStatusQueryRecord(
    bool IsFound,
    VerificationFlowStatus Status,
    DateTimeOffset ExpiresAt);
