namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record PhoneNumberQueryRecord
{
    public string PhoneNumber { get; init; } = string.Empty;

    public string? Region { get; init; }
    public Guid UniqueId { get; init; }
}