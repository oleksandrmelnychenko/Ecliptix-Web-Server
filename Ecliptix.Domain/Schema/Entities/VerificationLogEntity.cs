using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Schema.Entities;

public class VerificationLogEntity : EntityBase
{
    public Guid MembershipId { get; set; }
    public Guid MobileNumberId { get; set; }
    public Guid DeviceId { get; set; }
    public Guid? AccountId { get; set; }

    public VerificationPurpose Purpose { get; set; }
    public VerificationFlowStatus Status { get; set; }
    public short OtpCount { get; set; } = 0;

    public DateTimeOffset VerifiedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }

    public virtual MembershipEntity Membership { get; set; } = null!;
    public virtual MobileNumberEntity MobileNumber { get; set; } = null!;
    public virtual DeviceEntity Device { get; set; } = null!;
    public virtual AccountEntity? Account { get; set; }
}
