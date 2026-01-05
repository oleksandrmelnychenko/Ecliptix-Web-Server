using System.Security.Cryptography;
using Akka.Actor;
using Ecliptix.Core.Domain.Protocol;
using Ecliptix.Core.Services.KeyDerivation;
using Ecliptix.IdentityAccess.Domain.Memberships.ActorEvents.MasterKeyShares;
using Ecliptix.IdentityAccess.Domain.Memberships.Failures;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.IdentityAccess.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.IdentityAccess.Domain.Services.Security;
using Ecliptix.SharedKernel;
using Ecliptix.SharedKernel.Configuration;
using Ecliptix.SharedKernel.Actors;
using Ecliptix.SharedKernel.Failures;
using Ecliptix.SharedKernel.Failures.Sodium;
using Microsoft.Extensions.Options;
using Serilog;

namespace Ecliptix.Core.Services.Security;

internal sealed class MasterKeyService(
    ISecretSharingService secretSharingService,
    IEcliptixActorRegistry actorRegistry,
    IIdentityKeyDerivationService identityKeyDerivationService,
    IOptionsMonitor<SecurityConfiguration> securityConfig)
    : IMasterKeyService
{
    private readonly int _masterKeySize = securityConfig.CurrentValue.Cryptography.MasterKeySize;
    private readonly int _defaultThreshold = securityConfig.CurrentValue.Cryptography.DefaultThreshold;
    private readonly int _defaultTotalShares = securityConfig.CurrentValue.Cryptography.DefaultTotalShares;
    private readonly int _askTimeoutSeconds = securityConfig.CurrentValue.Cryptography.AskTimeoutSeconds;

    private const string RootKeyInfo = "ecliptix-protocol-root-key";
    private const string MasterKeyFingerprintInfo = "ecliptix-master-key-fingerprint";

    private const string ErrorMessageInsufficientShares = "Insufficient shares: found {0}, need at least 3";
    private const string ErrorMessageMetadataDeserializationFailed = "Failed to deserialize share metadata";

    private const string ErrorMessageUnexpectedReconstructionError =
        "Unexpected error during master key reconstruction";

    private const string ErrorMessagePersistSharesTimeout = "Timeout while persisting shares";
    private const string ErrorMessagePersistSharesFailed = "Failed to persist shares";
    private const string ErrorMessageRetrieveSharesTimeout = "Timeout while retrieving shares";
    private const string ErrorMessageRetrieveSharesFailed = "Failed to retrieve shares";
    private const string ErrorMessageMasterKeyReadFailed = "Failed to read master key bytes";

    private const string ErrorMessageUnexpectedIdentityKeyDerivationError =
        "Unexpected error during identity key derivation";

    private const string ErrorMessageSharesCheckFailed = "Unexpected error checking shares";

    public async Task<Result<dynamic, FailureBase>> GenerateRandomMasterKeyAndSplitAsync(Guid accountId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;

        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(accountId);
            if (sharesExistResult.IsOk && sharesExistResult.Unwrap())
            {
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this membership"));
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(_masterKeySize);

            if (allocateResult.IsErr)
            {
                SodiumFailure sodiumError = allocateResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to allocate master key handle: {sodiumError.Message}"));
            }

            masterKeyHandle = allocateResult.Unwrap();

            Result<byte[], SodiumFailure> randomBytesResult = SodiumInterop.GetRandomBytes(_masterKeySize);
            if (randomBytesResult.IsErr)
            {
                SodiumFailure sodiumError = randomBytesResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"Failed to generate random bytes: {sodiumError.Message}"));
            }

            byte[] randomBytes = randomBytesResult.Unwrap();
            try
            {
                Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(randomBytes);
                if (writeResult.IsErr)
                {
                    SodiumFailure sodiumError = writeResult.UnwrapErr();
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeyDerivationFailed(
                            $"Failed to write random bytes to handle: {sodiumError.Message}"));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(randomBytes);
            }

            Result<KeySplitResult, KeySplittingFailure> splitResult = await secretSharingService.SplitKeyAsync(
                masterKeyHandle,
                threshold: _defaultThreshold,
                totalShares: _defaultTotalShares,
                hmacKeyHandle: null);

            if (splitResult.IsErr)
            {
                KeySplittingFailure error = splitResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            KeySplitResult keySplitResult = splitResult.Unwrap();

            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(accountId, keySplitResult);

            if (persistResult.IsErr)
            {
                KeySplittingFailure error = persistResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error during master key generation: {ex.Message}",
                    ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
        }
    }

    public async Task<Result<dynamic, FailureBase>> SplitAndStoreMasterKeyAsync(byte[] masterKeyBytes,
        Guid accountId, bool allowOverwrite = false)
    {
        if (masterKeyBytes.Length != _masterKeySize)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeySplittingFailed($"Invalid master key size. Expected {_masterKeySize} bytes"));
        }

        SodiumSecureMemoryHandle? masterKeyHandle = null;

        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(accountId);

            if (sharesExistResult.IsOk && sharesExistResult.Unwrap())
            {
                if (!allowOverwrite)
                {
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeySplittingFailed("Master key shares already exist for this account"));
                }

                Result<Unit, KeySplittingFailure> deleteResult = await DeleteExistingSharesAsync(accountId);

                if (deleteResult.IsErr)
                {
                    return Result<dynamic, FailureBase>.Err(deleteResult.UnwrapErr());
                }
            }

            Result<SodiumSecureMemoryHandle, SodiumFailure> allocateResult =
                SodiumSecureMemoryHandle.Allocate(_masterKeySize);

            if (allocateResult.IsErr)
            {
                SodiumFailure sodiumError = allocateResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to allocate master key handle: {sodiumError.Message}"));
            }

            masterKeyHandle = allocateResult.Unwrap();

            Result<Unit, SodiumFailure> writeResult = masterKeyHandle.Write(masterKeyBytes);
            if (writeResult.IsErr)
            {
                SodiumFailure sodiumError = writeResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed(
                        $"Failed to write master key to handle: {sodiumError.Message}"));
            }

            Result<KeySplitResult, KeySplittingFailure> splitResult = await secretSharingService.SplitKeyAsync(
                masterKeyHandle,
                threshold: _defaultThreshold,
                totalShares: _defaultTotalShares,
                hmacKeyHandle: null);

            if (splitResult.IsErr)
            {
                KeySplittingFailure error = splitResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            KeySplitResult keySplitResult = splitResult.Unwrap();

            Result<InsertMasterKeySharesResult, KeySplittingFailure> persistResult =
                await PersistSharesAsync(accountId, keySplitResult);

            if (persistResult.IsErr)
            {
                KeySplittingFailure error = persistResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            Log.Information("[SERVER-MASTERKEY-SPLIT] Master key shares persisted successfully. AccountId: {AccountId}",
                accountId);

            return Result<dynamic, FailureBase>.Ok(keySplitResult);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error during master key splitting: {ex.Message}",
                    ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
        }
    }

    public async Task<Result<bool, FailureBase>> EnsureMasterKeyExistsAsync(Guid accountId)
    {
        try
        {
            Result<bool, FailureBase> sharesExistResult = await CheckSharesExistAsync(accountId);
            if (sharesExistResult.IsErr)
            {
                return Result<bool, FailureBase>.Err(sharesExistResult.UnwrapErr());
            }

            if (sharesExistResult.Unwrap())
            {
                return Result<bool, FailureBase>.Ok(true);
            }

            Result<dynamic, FailureBase> generateResult = await GenerateRandomMasterKeyAndSplitAsync(accountId);

            return generateResult.IsErr
                ? Result<bool, FailureBase>.Err(generateResult.UnwrapErr())
                : Result<bool, FailureBase>.Ok(true);
        }
        catch (Exception ex)
        {
            return Result<bool, FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed($"Unexpected error ensuring master key exists: {ex.Message}",
                    ex));
        }
    }

    public async Task<Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>> DeriveIdentityKeysAsync(
        Guid accountId)
    {
        Result<byte[], FailureBase> rootResult = await DeriveRootKeyAsync(accountId);
        if (rootResult.IsErr)
        {
            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(rootResult.UnwrapErr());
        }

        byte[]? rootKeyBytes = rootResult.Unwrap();
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        try
        {
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(accountId);
            if (reconstructResult.IsErr)
            {
                FailureBase error = reconstructResult.UnwrapErr();
                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(error);
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            Result<EcliptixSystemIdentityKeys, KeySplittingFailure> deriveResult =
                await identityKeyDerivationService.DeriveIdentityKeysFromMasterKeyAsync(masterKeyHandle, accountId);

            if (deriveResult.IsErr)
            {
                KeySplittingFailure error = deriveResult.UnwrapErr();
                return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(error);
            }

            EcliptixSystemIdentityKeys identityKeys = deriveResult.Unwrap();

            byte[] rootKeyToReturn = rootKeyBytes;
            rootKeyBytes = null;

            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Ok((identityKeys, rootKeyToReturn));
        }
        catch (Exception ex)
        {
            return Result<(dynamic IdentityKeys, byte[] RootKey), FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedIdentityKeyDerivationError, ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (rootKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(rootKeyBytes);
            }
        }
    }

    public async Task<Result<byte[], FailureBase>> DeriveRootKeyAsync(Guid accountId)
    {
        Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase> deriveResult =
            await DeriveRootKeyAndFingerprintAsync(accountId);
        if (deriveResult.IsErr)
        {
            return Result<byte[], FailureBase>.Err(deriveResult.UnwrapErr());
        }

        (byte[] rootKey, byte[] fingerprint) = deriveResult.Unwrap();
        CryptographicOperations.ZeroMemory(fingerprint);
        return Result<byte[], FailureBase>.Ok(rootKey);
    }

    public async Task<Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>>
        DeriveRootKeyAndFingerprintAsync(Guid accountId)
    {
        SodiumSecureMemoryHandle? masterKeyHandle = null;
        byte[]? masterKeyBytes = null;
        try
        {
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(accountId);
            if (reconstructResult.IsErr)
            {
                return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Err(
                    reconstructResult.UnwrapErr());
            }

            masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            Result<byte[], SodiumFailure> masterKeyReadResult = masterKeyHandle.ReadBytes(_masterKeySize);
            if (masterKeyReadResult.IsErr)
            {
                SodiumFailure error = masterKeyReadResult.UnwrapErr();
                return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Err(
                    KeySplittingFailure.KeyDerivationFailed($"{ErrorMessageMasterKeyReadFailed}: {error.Message}"));
            }

            masterKeyBytes = masterKeyReadResult.Unwrap();
            try
            {
                byte[] rootKeyBytes = new byte[_masterKeySize];

                byte[] saltBytes = accountId.ToByteArray();
                byte[] infoBytes = System.Text.Encoding.UTF8.GetBytes($"{RootKeyInfo}:v1:{accountId}");

                HKDF.DeriveKey(
                    HashAlgorithmName.SHA512,
                    ikm: masterKeyBytes,
                    output: rootKeyBytes,
                    salt: saltBytes,
                    info: infoBytes);

                byte[] fingerprintBytes = DeriveMasterKeyFingerprint(masterKeyBytes, accountId);

                return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Ok(
                    (rootKeyBytes, fingerprintBytes));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
        catch (Exception ex)
        {
            return Result<(byte[] RootKey, byte[] MasterKeyFingerprint), FailureBase>.Err(
                KeySplittingFailure.KeyDerivationFailed(ErrorMessageUnexpectedIdentityKeyDerivationError, ex));
        }
        finally
        {
            masterKeyHandle?.Dispose();
            if (masterKeyBytes != null)
            {
                CryptographicOperations.ZeroMemory(masterKeyBytes);
            }
        }
    }

    private static byte[] DeriveMasterKeyFingerprint(byte[] masterKeyBytes, Guid accountId)
    {
        byte[] infoBytes = System.Text.Encoding.UTF8.GetBytes($"{MasterKeyFingerprintInfo}:v1:{accountId}");
        using HMACSHA256 hmac = new(masterKeyBytes);
        return hmac.ComputeHash(infoBytes);
    }

    public async Task<Result<bool, FailureBase>> CheckSharesExistAsync(Guid accountId)
    {
        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(accountId);

            if (sharesResult.IsOk)
            {
                MasterKeyShareQueryRecord[] shares = sharesResult.Unwrap();
                return Result<bool, FailureBase>.Ok(shares.Length > 0);
            }

            KeySplittingFailure error = sharesResult.UnwrapErr();
            if (error.Type == KeySplittingFailureType.InsufficientShares)
            {
                return Result<bool, FailureBase>.Ok(false);
            }

            return Result<bool, FailureBase>.Err(error);
        }
        catch (Exception ex)
        {
            return Result<bool, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageSharesCheckFailed, ex));
        }
    }

    private async Task<Result<dynamic, FailureBase>> ReconstructMasterKeyAsync(Guid accountId)
    {
        try
        {
            Result<MasterKeyShareQueryRecord[], KeySplittingFailure> sharesResult =
                await RetrieveSharesAsync(accountId);

            if (sharesResult.IsErr)
            {
                KeySplittingFailure error = sharesResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            MasterKeyShareQueryRecord[] shareRecords = sharesResult.Unwrap();

            if (shareRecords.Length < _defaultThreshold)
            {
                return Result<dynamic, FailureBase>.Err(
                    KeySplittingFailure.KeyReconstructionFailed(string.Format(ErrorMessageInsufficientShares,
                        shareRecords.Length)));
            }

            List<KeyShare> shares = [];
            foreach (MasterKeyShareQueryRecord record in shareRecords)
            {
                ShareMetadata? metadata =
                    System.Text.Json.JsonSerializer.Deserialize<ShareMetadata>(record.ShareMetadata);
                if (metadata == null)
                {
                    return Result<dynamic, FailureBase>.Err(
                        KeySplittingFailure.KeyReconstructionFailed(ErrorMessageMetadataDeserializationFailed));
                }

                KeyShare share = new(
                    shareData: record.EncryptedShare,
                    index: record.ShareIndex,
                    location: Enum.Parse<ShareLocation>(record.StorageLocation),
                    sessionId: metadata.SessionId
                );

                shares.Add(share);
            }

            Result<SodiumSecureMemoryHandle, KeySplittingFailure> reconstructResult =
                await secretSharingService.ReconstructKeyHandleAsync(shares.ToArray(), hmacKeyHandle: null);

            if (reconstructResult.IsErr)
            {
                KeySplittingFailure error = reconstructResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            SodiumSecureMemoryHandle masterKeyHandle = reconstructResult.Unwrap();

            return Result<dynamic, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageUnexpectedReconstructionError, ex));
        }
    }

    private async Task<Result<InsertMasterKeySharesResult, KeySplittingFailure>> PersistSharesAsync(
        Guid accountId, KeySplitResult keySplitResult)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            List<ShareData> shareDataList = [];
            shareDataList.AddRange(from share in keySplitResult.Shares
                let metadata =
                    System.Text.Json.JsonSerializer.Serialize(new
                    {
                        ShareId = Convert.ToBase64String(share.ShareId),
                        SessionId = share.SessionId,
                        CreatedAt = share.CreatedAt,
                        HasHmac = share.Hmac != null
                    })
                select new ShareData(share.ShareIndex, share.ShareData, metadata, share.Location.ToString()));

            InsertMasterKeySharesEvent insertEvent = new(
                accountId,
                shareDataList
            );

            Result<InsertMasterKeySharesResult, MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<InsertMasterKeySharesResult, MasterKeyFailure>>(
                    insertEvent,
                    TimeSpan.FromSeconds(_askTimeoutSeconds));

            return result.Match(
                ok => Result<InsertMasterKeySharesResult, KeySplittingFailure>.Ok(ok),
                err => Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed($"{ErrorMessagePersistSharesFailed}: {err.Message}",
                        err.InnerException)));
        }
        catch (TimeoutException)
        {
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed(ErrorMessagePersistSharesTimeout));
        }
        catch (Exception ex)
        {
            return Result<InsertMasterKeySharesResult, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"{ErrorMessagePersistSharesFailed}: {ex.Message}", ex));
        }
    }

    private async Task<Result<MasterKeyShareQueryRecord[], KeySplittingFailure>> RetrieveSharesAsync(Guid accountId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            GetMasterKeySharesEvent getEvent = new(accountId);

            Result<MasterKeyShareQueryRecord[], MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<MasterKeyShareQueryRecord[], MasterKeyFailure>>(
                    getEvent,
                    TimeSpan.FromSeconds(_defaultTotalShares));

            return result.Match(
                ok => Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Ok(ok),
                err => err.Message.Contains(MasterKeyMessageKeys.SharesNotFound)
                    ? Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Ok(
                        System.Array.Empty<MasterKeyShareQueryRecord>())
                    : Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                        KeySplittingFailure.KeyReconstructionFailed(
                            $"{ErrorMessageRetrieveSharesFailed}: {err.Message}",
                            err.InnerException)));
        }
        catch (TimeoutException)
        {
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed(ErrorMessageRetrieveSharesTimeout));
        }
        catch (Exception ex)
        {
            return Result<MasterKeyShareQueryRecord[], KeySplittingFailure>.Err(
                KeySplittingFailure.KeyReconstructionFailed($"{ErrorMessageRetrieveSharesFailed}: {ex.Message}", ex));
        }
    }

    private async Task<Result<Unit, KeySplittingFailure>> DeleteExistingSharesAsync(Guid accountId)
    {
        try
        {
            IActorRef masterKeySharePersistor = actorRegistry.Get(ActorIds.MasterKeySharePersistorActor);
            DeleteMasterKeySharesEvent deleteEvent = new(accountId);

            Result<Unit, MasterKeyFailure> result =
                await masterKeySharePersistor.Ask<Result<Unit, MasterKeyFailure>>(
                    deleteEvent,
                    TimeSpan.FromSeconds(_defaultTotalShares));

            return result.Match(
                ok => Result<Unit, KeySplittingFailure>.Ok(ok),
                err => Result<Unit, KeySplittingFailure>.Err(
                    KeySplittingFailure.KeySplittingFailed($"Failed to delete existing shares: {err.Message}",
                        err.InnerException)));
        }
        catch (TimeoutException)
        {
            return Result<Unit, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed("Timeout while deleting existing shares"));
        }
        catch (Exception ex)
        {
            return Result<Unit, KeySplittingFailure>.Err(
                KeySplittingFailure.KeySplittingFailed($"Failed to delete existing shares: {ex.Message}", ex));
        }
    }

    public async Task<Result<dynamic, FailureBase>> GetMasterKeyHandleAsync(Guid accountId)
    {
        try
        {
            Result<dynamic, FailureBase> reconstructResult = await ReconstructMasterKeyAsync(accountId);
            if (reconstructResult.IsErr)
            {
                FailureBase error = reconstructResult.UnwrapErr();
                return Result<dynamic, FailureBase>.Err(error);
            }

            SodiumSecureMemoryHandle masterKeyHandle = (SodiumSecureMemoryHandle)reconstructResult.Unwrap();

            return Result<dynamic, FailureBase>.Ok(masterKeyHandle);
        }
        catch (Exception ex)
        {
            return Result<dynamic, FailureBase>.Err(
                KeySplittingFailure.KeyReconstructionFailed(
                    $"Unexpected error retrieving master key handle: {ex.Message}", ex));
        }
    }
}
