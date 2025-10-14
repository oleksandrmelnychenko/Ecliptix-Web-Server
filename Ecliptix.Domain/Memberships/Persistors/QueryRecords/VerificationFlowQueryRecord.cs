using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record VerificationFlowQueryRecord
{
    public required Guid UniqueIdentifier { get; init; }
    public required Guid MobileNumberIdentifier { get; init; }
    public required Guid AppDeviceIdentifier { get; init; }
    public uint? ConnectId { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required VerificationPurpose Purpose { get; init; }
    public required VerificationFlowStatus Status { get; init; }
    public required int OtpCount { get; init; }
    public OtpQueryRecord? OtpActive { get; init; }
}