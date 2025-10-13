namespace Ecliptix.Domain.Account.Persistors.QueryRecords;

public record MasterKeyShareQueryRecord
{
    public required Guid AccountUniqueId { get; init; }
    public required int ShareIndex { get; init; }
    public required byte[] EncryptedShare { get; init; }
    public required string ShareMetadata { get; init; }
    public required string StorageLocation { get; init; }
    public required Guid UniqueId { get; init; }
    public required int CredentialsVersion { get; init; }
}
