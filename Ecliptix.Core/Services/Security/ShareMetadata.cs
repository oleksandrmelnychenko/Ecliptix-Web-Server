namespace Ecliptix.Core.Services.Security;

internal class ShareMetadata
{
    public string ShareId { get; set; } = string.Empty;
    public Guid SessionId { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool HasHmac { get; set; }
    public int EncryptionVersion { get; set; }
    public string? EncryptionNonce { get; set; }
    public string? EncryptionTag { get; set; }
}
