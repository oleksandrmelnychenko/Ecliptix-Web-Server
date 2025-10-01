using System.Threading.Tasks;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;

namespace Ecliptix.Security.KeyDerivation;

public interface ISecretSharingService
{
    Task<Result<Unit, KeySplittingFailure>> SecurelyDisposeSharesAsync(KeyShare[] shares);

    Task<Result<KeySplitResult, KeySplittingFailure>> SplitKeyAsync(SodiumSecureMemoryHandle keyHandle, int threshold = 3, int totalShares = 5, SodiumSecureMemoryHandle? hmacKeyHandle = null);

    Task<Result<SodiumSecureMemoryHandle, KeySplittingFailure>> ReconstructKeyHandleAsync(KeyShare[] shares, SodiumSecureMemoryHandle? hmacKeyHandle = null);
}