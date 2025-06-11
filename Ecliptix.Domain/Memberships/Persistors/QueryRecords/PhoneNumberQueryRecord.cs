using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record PhoneNumberQueryRecord(
    string PhoneNumber,
    string? RegionCode)
{
    public Guid UniqueIdentifier { get; init; }
}