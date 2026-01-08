using Ecliptix.IdentityAccess.Domain.Memberships;
namespace Ecliptix.IdentityAccess.Domain.Schema.Entities;

public class VerificationFlowEntity : EntityBase
{
    public Guid MobileNumberId { get; set; }
    public Guid AppDeviceId { get; set; }

    public VerificationFlowStatus Status { get; set; } = VerificationFlowStatus.Pending;
    public VerificationPurpose Purpose { get; set; } = VerificationPurpose.Unspecified;
    public short OtpCount { get; set; }
    public long? ConnectionId { get; set; }
    public DateTimeOffset? LastOtpSentAt { get; set; }
    public DateTimeOffset? ResendAvailableAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public MobileNumberEntity MobileNumber { get; set; } = null!;
    public DeviceEntity AppDevice { get; set; } = null!;

    public List<OtpCodeEntity> OtpCodes
    {
        get => field ??= [];
        set;
    }

    public List<MembershipEntity> Memberships
    {
        get => field ??= [];
        set;
    }
}
