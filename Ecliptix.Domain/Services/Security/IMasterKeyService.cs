using Ecliptix.Utilities;
using Ecliptix.Utilities.Failures;

namespace Ecliptix.Domain.Services.Security;

public interface IMasterKeyService
{
    Task<Result<dynamic, FailureBase>> DeriveMasterKeyAndSplitAsync(
        dynamic sessionKeyHandle,
        Guid membershipId);

    Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(Guid membershipId);

    Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid membershipId);

    Task<Result<dynamic, FailureBase>> RegenerateMasterKeySharesAsync(
        dynamic newSessionKey, Guid membershipId);

    Task<Result<string, FailureBase>> ValidateMasterKeySharesAsync(
        dynamic sessionKeyHandle, Guid membershipId);

    Task<Result<dynamic, FailureBase>> GetMasterKeyHandleAsync(Guid membershipId);
}
