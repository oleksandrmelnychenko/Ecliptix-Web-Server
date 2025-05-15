using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Persistors.QueryRecords;

public record PhoneNumberQueryRecord(
    string PhoneNumber,
    string? RegionCode,
    CustomPhoneNumberType PhoneType)
{
    public Guid UniqueIdentifier { get; init; }
}