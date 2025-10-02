namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record LoginMembershipResult
{
    public Guid? MembershipUniqueId { get; init; }
    public string? Status { get; init; }
    public string Outcome { get; init; } = string.Empty;
    public byte[] SecureKey { get; init; } = [];
    public byte[] MaskingKey { get; init; } = [];
    public string? ErrorMessage { get; init; }
}