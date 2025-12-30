using Ecliptix.Utilities;

namespace Ecliptix.Domain.Services.Security;

public interface IMasterKeyService
{
    Task<Result<dynamic, FailureBase>> SplitAndStoreMasterKeyAsync(byte[] masterKeyBytes, Guid accountId,
        bool allowOverwrite = false);

    Task<Result<bool, FailureBase>> EnsureMasterKeyExistsAsync(Guid accountId);

    Task<Result<byte[], FailureBase>> DeriveRootKeyAsync(Guid accountId);

    Task<Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>> DeriveRootKeyAndFingerprintAsync(
        Guid accountId);

    Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(Guid accountId);

    Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid accountId);

    Task<Result<dynamic, FailureBase>> GetMasterKeyHandleAsync(Guid accountId);
}
