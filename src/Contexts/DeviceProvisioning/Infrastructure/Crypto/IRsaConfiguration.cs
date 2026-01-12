namespace Ecliptix.DeviceProvisioning.Infrastructure.Crypto;

public interface IRsaConfiguration
{
    int EncryptedBlockSize { get; }
    int MaxPlaintextSize { get; }
    int OptimalChunkSize { get; }
}
