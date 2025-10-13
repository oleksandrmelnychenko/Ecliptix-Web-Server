namespace Ecliptix.Domain.Account.ActorEvents;

public record ShareData(
    int ShareIndex,
    byte[] EncryptedShare,
    string ShareMetadata,
    string StorageLocation
);

public record InsertMasterKeySharesEvent(
    Guid AccountUniqueId,
    IReadOnlyList<ShareData> Shares
);
