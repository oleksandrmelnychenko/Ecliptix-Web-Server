namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record MobileNumberQueryRecord
{
    public string MobileNumber { get; init; } = string.Empty;
    public string? Region { get; init; }
    public Guid UniqueId { get; init; }
}