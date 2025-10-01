using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;

namespace Ecliptix.Core.Services.KeyDerivation;

public interface IHardenedKeyDerivation
{
    Task<Result<SodiumSecureMemoryHandle, KeySplittingFailure>> DeriveEnhancedMasterKeyHandleAsync(
        SodiumSecureMemoryHandle baseKeyHandle,
        string context,
        KeyDerivationOptions options);
}

public class KeyDerivationOptions
{
    public int MemorySize { get; set; } = 262144;
    public int Iterations { get; set; } = 4;
    public int DegreeOfParallelism { get; set; } = 4;
    public bool UseHardwareEntropy { get; set; } = true;
    public int OutputLength { get; set; } = 64;
}
