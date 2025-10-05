using Ecliptix.Security.Certificate.Pinning.NativeResolver;

namespace Ecliptix.Core.Infrastructure.Crypto;

public class RsaConfiguration : IRsaConfiguration
{
    public int KeySize => CertificatePinningConfigurationConstants.RsaKeySize;
    public int EncryptedBlockSize => CertificatePinningConfigurationConstants.RsaEncryptedBlockSize;
    public int MaxPlaintextSize => CertificatePinningConfigurationConstants.RsaMaxPlaintextSize;
    public int OptimalChunkSize => CertificatePinningConfigurationConstants.RsaOptimalChunkSize;
    public RsaPaddingMode PaddingMode => RsaPaddingMode.Oaep;
}