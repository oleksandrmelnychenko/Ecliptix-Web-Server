namespace Ecliptix.Domain.Schema.Entities;

public class MasterKeyShareEntity : EntityBase
{
    public Guid MembershipUniqueId { get; set; }

    public int ShareIndex { get; set; }
    public byte[] EncryptedShare { get; set; } = null!;
    public string ShareMetadata { get; set; } = null!;
    public string StorageLocation { get; set; } = null!;
    public int CredentialsVersion { get; set; }

    public virtual MembershipEntity Membership { get; set; } = null!;
}
