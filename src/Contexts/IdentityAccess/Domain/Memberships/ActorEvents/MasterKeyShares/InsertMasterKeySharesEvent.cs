using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.Common;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MasterKeyShares;

public record ShareData(
    int ShareIndex,
    byte[] EncryptedShare,
    string ShareMetadata,
    string StorageLocation
);

public record InsertMasterKeySharesEvent(
    Guid AccountUniqueId,
    IReadOnlyList<ShareData> Shares,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
