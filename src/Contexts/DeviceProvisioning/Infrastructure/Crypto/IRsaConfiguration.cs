namespace Ecliptix.DeviceProvisioning.Infrastructure.Crypto;

public enum RsaPaddingMode
{
    Oaep
}

public interface IRsaConfiguration
{
    int EncryptedBlockSize { get; }
    int MaxPlaintextSize { get; }
    int OptimalChunkSize { get; }
}
