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

    public MembershipEntity Membership { get; set; } = null!;
    public MobileNumberEntity MobileNumber { get; set; } = null!;
    public DeviceEntity Device { get; set; } = null!;
    public AccountEntity? Account { get; set; }
}
