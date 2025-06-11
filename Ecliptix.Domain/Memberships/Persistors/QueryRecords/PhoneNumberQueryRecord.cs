using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record PhoneNumberQueryRecord(
    string PhoneNumber,
    string? RegionCode)
{
    public Guid UniqueIdentifier { get; init; }
}

internal class PhoneNumberQueryResult
{
    public string PhoneNumber { get; set; } = string.Empty;
    public string? Region { get; set; }
    
    public Guid UniqueId { get; set; }
}