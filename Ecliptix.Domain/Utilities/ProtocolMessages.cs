namespace Ecliptix.Domain.Utilities;

public static class ProtocolMessages
{
    public const string FailedToExportIdentityKeys = "Failed to export identity keys to proto state.";
    public const string ProtoStateIsNull = "Proto state is null.";
    public const string Ed25519SecretKeyNullOrEmpty = "Ed25519 secret key is null or empty.";
    public const string IdentityX25519SecretKeyNullOrEmpty = "Identity X25519 secret key is null or empty.";
    public const string SignedPrekeySecretNullOrEmpty = "Signed prekey secret is null or empty.";
    public const string Ed25519PublicKeyNullOrEmpty = "Ed25519 public key is null or empty.";
    public const string IdentityX25519PublicKeyNullOrEmpty = "Identity X25519 public key is null or empty.";
    public const string SignedPrekeyPublicKeyNullOrEmpty = "Signed prekey public key is null or empty.";
    public const string SignedPrekeySignatureNullOrEmpty = "Signed prekey signature is null or empty.";
    
    public const string InvalidEd25519SecretKeyLength = "Invalid Ed25519 secret key length.";
    public const string InvalidX25519IdentitySecretKeyLength = "Invalid X25519 identity secret key length.";
    public const string InvalidSignedPrekeySecretKeyLength = "Invalid signed prekey secret key length.";
    public const string InvalidEd25519PublicKeyLength = "Invalid Ed25519 public key length.";
    public const string KeyMaterialLengthMismatch = "Key material must be exactly {0} bytes long, but was {1}.";
    public const string DestinationBufferTooSmall = "Destination buffer must be at least {0} bytes, but was {1}.";
    public const string ChainKeyLengthMismatch = "Chain key must be {0} bytes";
    public const string OPKPrivateKeyNullOrEmpty = "OPK private key is null or empty for ID {0}.";
    public const string OPKPublicKeyNullOrEmpty = "OPK public key is null or empty for ID {0}.";
    
    public const string NoPerformanceDataCollected = "No performance data collected.";
    public const string OperationHeader = "Operation";
    public const string CountHeader = "Count";
    public const string AverageHeader = "Avg(ms)";
    public const string MaxHeader = "Max(ms)";
    public const string MinHeader = "Min(ms)";
}