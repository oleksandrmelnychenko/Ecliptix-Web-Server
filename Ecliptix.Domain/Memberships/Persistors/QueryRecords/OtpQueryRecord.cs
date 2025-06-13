namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record OtpQueryRecord
{
    public Guid UniqueIdentifier { get; init; }
    public Guid FlowUniqueId { get; init; }
    public Guid PhoneNumberIdentifier { get; init; }
    public required string OtpHash { get; init; }
    public required string OtpSalt { get; init; }
    public required DateTime ExpiresAt { get; init; }
    public required VerificationFlowStatus Status { get; init; }
    public required bool IsActive { get; init; }
}