using Ecliptix.Utilities;

namespace Ecliptix.Domain.Services.Security;

public interface IMasterKeyService
{
    Task<Result<dynamic, FailureBase>> SplitAndStoreMasterKeyAsync(byte[] masterKeyBytes, Guid membershipId, bool allowOverwrite = false);

    Task<Result<bool, FailureBase>> EnsureMasterKeyExistsAsync(Guid membershipId);

    Task<Result<byte[], FailureBase>> DeriveRootKeyAsync(Guid membershipId);

    Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(Guid membershipId);

    Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid membershipId);

    Task<Result<dynamic, FailureBase>> GetMasterKeyHandleAsync(Guid membershipId);
}
