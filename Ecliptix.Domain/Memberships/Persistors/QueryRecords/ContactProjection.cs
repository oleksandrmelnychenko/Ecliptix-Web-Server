namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record ContactProjection
{
    public long RelationId { get; init; }
    public bool IsInitiator { get; init; }
    public Guid ContactMembershipId { get; init; }
    public string? DisplayName { get; init; }
    public string? ProfileName { get; init; }
    public byte? Status { get; init; }
    public DateTimeOffset? MutedUntil { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}
