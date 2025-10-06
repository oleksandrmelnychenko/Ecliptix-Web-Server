
namespace Ecliptix.Domain.Schema.Entities;

public class MembershipAttempt : EntityBase
{
    public Guid MembershipId { get; set; }
    public string AttemptType { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;

    public virtual Membership Membership { get; set; } = null!;
}