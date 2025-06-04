using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record VerificationFlowQueryRecord(
    Guid UniqueIdentifier,                      
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier,
    uint ConnectId
)
{
    public DateTime ExpiresAt { get; init; }
    public VerificationPurpose Purpose { get; init; }
    
    public VerificationFlowStatus Status { get; init; }
    public int OtpCount { get; init; }

    public Option<OtpQueryRecord> OtpActive { get; init; } = Option<OtpQueryRecord>.None;
}
