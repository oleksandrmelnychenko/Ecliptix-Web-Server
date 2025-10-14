using Ecliptix.Domain.Schema.Interfaces;

namespace Ecliptix.Domain.Schema.Entities;

public class DeviceContextEntity : EntityBase, IExpirable
{
    public Guid MembershipId { get; set; }
    public Guid DeviceId { get; set; }
    public Guid? ActiveAccountId { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTimeOffset ContextEstablishedAt { get; set; }
    public DateTimeOffset ContextExpiresAt { get; set; }
    public DateTimeOffset? LastActivityAt { get; set; }

    public DateTimeOffset ExpiresAt => ContextExpiresAt;

    public virtual MembershipEntity Membership { get; set; } = null!;
    public virtual DeviceEntity Device { get; set; } = null!;
    public virtual AccountEntity? ActiveAccount { get; set; }
}
