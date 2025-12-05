using Ecliptix.Domain.Memberships;

namespace Ecliptix.Domain.Schema.Entities;

public class MembershipEntity : EntityBase
{
    public Guid MobileNumberId { get; set; }
    public Guid AppDeviceId { get; set; }
    public Guid? VerificationFlowId { get; set; }

    public MembershipStatus Status { get; set; } = MembershipStatus.Inactive;
    public MembershipCreationStatus? CreationStatus { get; set; }

    public MobileNumberEntity MobileNumber { get; set; } = null!;
    public DeviceEntity AppDevice { get; set; } = null!;
    public VerificationFlowEntity? VerificationFlow { get; set; }

    public List<LoginAttemptEntity> LoginAttempts
    {
        get => field ??= [];
        set;
    }

    public List<MasterKeyShareEntity> MasterKeyShares
    {
        get => field ??= [];
        set;
    }

    public List<AccountEntity> Accounts
    {
        get => field ??= [];
        set;
    }

    public List<DeviceContextEntity> DeviceContexts
    {
        get => field ??= [];
        set;
    }

    public List<VerificationLogEntity> VerificationLogs
    {
        get => field ??= [];
        set;
    }
}
