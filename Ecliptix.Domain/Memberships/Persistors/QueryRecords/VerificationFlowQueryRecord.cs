using Ecliptix.Domain.Utilities;
using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record VerificationFlowQueryRecord(
    Guid UniqueIdentifier,                      
    Guid PhoneNumberIdentifier,
    Guid AppDeviceIdentifier
)
{
    public uint? ConnectId { get; init; }
    public required DateTime ExpiresAt { get; init; }
    public required VerificationPurpose Purpose { get; init; }
    public required VerificationFlowStatus Status { get; init; }
    public required int OtpCount { get; init; }

    public Option<OtpQueryRecord> OtpActive { get; init; } = Option<OtpQueryRecord>.None;
}