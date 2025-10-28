using Ecliptix.Protobuf.Membership;

namespace Ecliptix.Domain.Memberships.Persistors.QueryRecords;

public record MembershipQueryRecord
{
    public required Guid UniqueIdentifier { get; init; }
    public required Guid DeviceId { get; init; }
    public required Membership.Types.ActivityStatus ActivityStatus { get; init; }
    public Membership.Types.CreationStatus CreationStatus { get; init; }
    public int CredentialsVersion { get; init; } = 1;
    public byte[] SecureKey { get; init; } = [];
    public byte[] MaskingKey { get; init; } = [];
    public List<AccountInfo> AvailableAccounts { get; init; } = new();
    public Guid? ActiveAccountId { get; init; }
}
