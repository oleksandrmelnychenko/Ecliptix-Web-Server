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
    
    public bool IsEmpty =>
        ConnectId == 0 &&
        StreamId == Guid.Empty &&
        string.IsNullOrEmpty(Mobile) &&
        AppDeviceUniqueRec == Guid.Empty &&
        string.IsNullOrEmpty(Code) &&
        ExpiresAt == default &&
        Status == default;
    
    public static readonly VerificationSessionQueryRecord Empty = new(
        ConnectId: 0,
        StreamId: Guid.Empty,
        Mobile: string.Empty,
        AppDeviceUniqueRec: Guid.Empty,
        Code: string.Empty)
    {
        ExpiresAt = default,
        Status = default
    };
}

