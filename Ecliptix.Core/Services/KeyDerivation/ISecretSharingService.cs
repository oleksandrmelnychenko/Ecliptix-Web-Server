using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Failures;

namespace Ecliptix.Core.Services.KeyDerivation;

public interface ISecretSharingService
{
    Task<Result<KeySplitResult, KeySplittingFailure>> SplitKeyAsync(SodiumSecureMemoryHandle keyHandle, int threshold = 3, int totalShares = 5, SodiumSecureMemoryHandle? hmacKeyHandle = null);

    Task<Result<SodiumSecureMemoryHandle, KeySplittingFailure>> ReconstructKeyHandleAsync(KeyShare[] shares, SodiumSecureMemoryHandle? hmacKeyHandle = null);
}
