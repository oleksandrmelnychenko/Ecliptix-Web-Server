using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents;

public record ShareData(
    int ShareIndex,
    byte[] EncryptedShare,
    string ShareMetadata,
    string StorageLocation
);

public record DeleteMasterKeySharesEvent(
    Guid AccountId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMasterKeySharesEvent(
    Guid AccountUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record InsertMasterKeySharesEvent(
    Guid AccountUniqueId,
    IReadOnlyList<ShareData> Shares,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
