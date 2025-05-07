using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Persistors.QueryRecords;

public record VerificationSessionQueryRecord(
    uint ConnectId,
    Guid StreamId,
    string Mobile,
    Guid AppDeviceUniqueRec,
    string Code)
{
    public DateTime ExpiresAt { get; init; }
    public MembershipVerificationSessionStatus Status { get; init; }
}