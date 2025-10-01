namespace Ecliptix.Domain.Memberships.ActorEvents;

public record ShareData(
    int ShareIndex,
    byte[] EncryptedShare,
    string ShareMetadata,
    string StorageLocation
);

public record InsertMasterKeySharesEvent(
    Guid MembershipUniqueId,
    IReadOnlyList<ShareData> Shares
);
