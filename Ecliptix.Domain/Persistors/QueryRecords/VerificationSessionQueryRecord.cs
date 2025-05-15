using Ecliptix.Domain.Memberships;
using Ecliptix.Protobuf.Authentication;

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
    public int OtpCount { get; init; }
}
