using Ecliptix.Domain.Memberships;
using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Persistors.QueryRecords;

public record VerificationSessionQueryRecord(
    Guid UniqueIdentifier,                      
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier,
    uint ConnectId
)
{
    public DateTime ExpiresAt { get; init; }
    public VerificationPurpose Purpose { get; init; }
    
    public VerificationSessionStatus Status { get; init; }
    public int OtpCount { get; init; }

    public Option<OtpQueryRecord> OtpActive { get; init; } = Option<OtpQueryRecord>.None;
}
