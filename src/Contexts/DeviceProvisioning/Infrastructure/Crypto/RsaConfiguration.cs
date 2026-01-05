using Ecliptix.Security.Certificate.Pinning.NativeResolver;

namespace Ecliptix.DeviceProvisioning.Infrastructure.Crypto;

public class RsaConfiguration : IRsaConfiguration
{
    public int EncryptedBlockSize => CertificatePinningConfigurationConstants.RsaEncryptedBlockSize;
    public int MaxPlaintextSize => CertificatePinningConfigurationConstants.RsaMaxPlaintextSize;
    public int OptimalChunkSize => CertificatePinningConfigurationConstants.RsaOptimalChunkSize;
}
