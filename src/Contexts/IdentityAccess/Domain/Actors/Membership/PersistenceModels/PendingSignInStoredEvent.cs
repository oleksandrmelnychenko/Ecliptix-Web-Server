using Ecliptix.IdentityAccess.Domain.Persistors.QueryRecords;
using ProtoMembership = Ecliptix.Protobuf.Membership.Membership;

namespace Ecliptix.IdentityAccess.Domain.Actors.Membership.PersistenceModels;

internal sealed record PendingSignInStoredEvent(
    uint ConnectId,
    Guid MembershipId,
    Guid MobileNumberId,
    string MobileNumber,
    ProtoMembership.Types.ActivityStatus ActivityStatus,
    ProtoMembership.Types.CreationStatus CreationStatus,
    DateTimeOffset CreatedAt,
    byte[]? ServerMac,
    List<AccountInfo>? AvailableAccounts,
    Guid? ActiveAccountId,
    int OpaqueKeyVersion = 1);
