namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record PendingRequestQueryRecord
{
    public required Guid MembershipId { get; init; }
    public required DateTimeOffset RequestedAt { get; init; }
    public string? Message { get; init; }
    public string? DisplayName { get; init; }
    public string? AvatarUrl { get; init; }
}
