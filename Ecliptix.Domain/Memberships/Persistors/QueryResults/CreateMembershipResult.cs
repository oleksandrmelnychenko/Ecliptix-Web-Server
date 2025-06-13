namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record CreateMembershipResult
{
    public Guid? MembershipUniqueId { get; init; }
    public string? Status { get; init; }
    public string? CreationStatus { get; init; }
    public string Outcome { get; init; } = string.Empty;
}