namespace Ecliptix.Domain.Memberships.Persistors.QueryResults;

internal record UpdateSecureKeyResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public Guid? MembershipUniqueId { get; init; }
    public string? Status { get; init; }
    public string? CreationStatus { get; init; }
    public byte[] MaskingKey { get; init; } = [];
}