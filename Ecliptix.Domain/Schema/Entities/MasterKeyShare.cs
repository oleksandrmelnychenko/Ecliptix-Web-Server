namespace Ecliptix.Domain.Schema.Entities;

public class MasterKeyShare : EntityBase
{
    public Guid MembershipUniqueId { get; set; }
    public int ShareIndex { get; set; }
    public byte[] EncryptedShare { get; set; } = null!;
    public string ShareMetadata { get; set; } = null!;
    public string StorageLocation { get; set; } = null!;
    public int CredentialsVersion { get; set; }

    public virtual Membership Membership { get; set; } = null!;
}

