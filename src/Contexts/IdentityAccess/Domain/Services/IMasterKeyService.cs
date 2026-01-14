using Ecliptix.SharedKernel;

namespace Ecliptix.IdentityAccess.Domain.Services;

public interface IMasterKeyService
{
    Task<Result<Unit, FailureBase>> SplitAndStoreMasterKeyAsync(byte[] masterKeyBytes, Guid accountId,
        bool allowOverwrite = false);

    Task<Result<bool, FailureBase>> EnsureMasterKeyExistsAsync(Guid accountId);

    Task<Result<byte[], FailureBase>> DeriveRootKeyAsync(Guid accountId);

    Task<Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>>
        DeriveRootKeyAndFingerprintAsync(Guid accountId);

    Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(Guid accountId);

    Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid accountId);

    Task<Result<SodiumSecureMemoryHandle, FailureBase>> GetMasterKeyHandleAsync(Guid accountId);
}
