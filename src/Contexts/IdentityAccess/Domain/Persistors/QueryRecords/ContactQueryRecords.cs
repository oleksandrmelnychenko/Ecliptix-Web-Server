
namespace Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;

public record ContactQueryRecord
{
    public required Guid MembershipId { get; init; }
    public required DateTimeOffset? Since { get; init; }
    public string? DisplayName { get; init; }
    public string? AvatarUrl { get; init; }
}
