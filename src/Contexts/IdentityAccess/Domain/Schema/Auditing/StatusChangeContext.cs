namespace Ecliptix.IdentityAccess.Domain.Schema.Auditing;

public sealed class StatusChangeContext
{
    public Guid? MembershipId { get; init; }
    public Guid? AccountId { get; init; }
    public Guid? DeviceId { get; init; }
    public string? Source { get; init; }
    public string? Reason { get; init; }
    public string? CorrelationId { get; init; }
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
