using Ecliptix.SharedKernel.Actors;

namespace Ecliptix.IdentityAccess.Domain.Actors.Membership;

public record ShareData(
    int ShareIndex,
    byte[] EncryptedShare,
    string ShareMetadata,
    string StorageLocation
);

public record DeleteMasterKeySharesCommand(
    Guid AccountId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record GetMasterKeySharesQuery(
    Guid AccountUniqueId,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;

public record CreateMasterKeySharesCommand(
    Guid AccountUniqueId,
    IReadOnlyList<ShareData> Shares,
    CancellationToken CancellationToken = default
) : ICancellableActorEvent;
