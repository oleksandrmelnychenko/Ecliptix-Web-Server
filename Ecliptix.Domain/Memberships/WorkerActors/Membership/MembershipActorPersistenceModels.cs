using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Protobuf.Membership;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.Domain.Memberships.WorkerActors.Membership;

internal sealed record PendingSignInStoredEvent(
    uint ConnectId,
    Guid MembershipId,
    Guid MobileNumberId,
    string MobileNumber,
    ProtoMembership.Types.ActivityStatus ActivityStatus,
    ProtoMembership.Types.CreationStatus CreationStatus,
    DateTimeOffset CreatedAt,
    byte[] ServerMac,
    List<AccountInfo>? AvailableAccounts,
    Guid? ActiveAccountId);

internal sealed record PendingSignInRemovedEvent(uint ConnectId);

internal sealed record RegistrationMaskingKeyStoredEvent(Guid MembershipId, byte[] MaskingKey);

internal sealed record RegistrationMaskingKeyRemovedEvent(Guid MembershipId);

internal sealed record RecoverySessionStartedEvent(Guid MembershipId, byte[] MaskingKey, byte[] SessionKey, DateTimeOffset StartedAt);

internal sealed record RecoverySessionClearedEvent(Guid MembershipId);

internal sealed record MembershipActorSnapshot(
    List<PendingSignInStoredEvent> PendingSignIns,
    List<RegistrationMaskingKeyStoredEvent> PendingMaskingKeys,
    List<RecoverySessionSnapshot> RecoverySessions);

internal sealed record RecoverySessionSnapshot(Guid MembershipId, byte[] SessionKey, DateTimeOffset StartedAt);
