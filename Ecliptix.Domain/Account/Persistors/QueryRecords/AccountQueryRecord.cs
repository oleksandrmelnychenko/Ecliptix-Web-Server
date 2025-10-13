namespace Ecliptix.Domain.Account.Persistors.QueryRecords;

public record AccountQueryRecord
{
    public required Guid UniqueIdentifier { get; init; }
    public required Ecliptix.Protobuf.Account.Account.Types.ActivityStatus ActivityStatus { get; init; }
    public Ecliptix.Protobuf.Account.Account.Types.CreationStatus CreationStatus { get; init; }
    public int CredentialsVersion { get; init; } = 1;

    public byte[] SecureKey { get; init; } = [];
    public byte[] MaskingKey { get; init; } = [];
}